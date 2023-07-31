// Copyright 2014 Andrew Oates.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "arch/memory/page_map.h"
#include "common/kassert.h"
#include "common/errno.h"
#include "memory/kmalloc.h"
#include "memory/vm.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/process-internal.h"
#include "proc/scheduler.h"
#include "vfs/vfs.h"

typedef struct {
  proc_func_t start;
  void* arg;
} proc_start_args_t;

static void* proc_fork_trampoline(void* arg) {
  proc_start_args_t* args = (proc_start_args_t*)arg;

  proc_func_t start_func = args->start;
  void* start_arg = args->arg;
  kfree(args);

  (*start_func)(start_arg);

  proc_exit(0);
  die("unreachable");
  return 0x0;
}

int proc_fork(proc_func_t start, void* arg) {
  process_t* new_process = proc_alloc();
  if (!new_process) return -ENOMEM;

  new_process->user_arch = proc_current()->user_arch;

  // Fork VFS handles.
  vfs_fork_fds(proc_current(), new_process);
  new_process->cwd = proc_current()->cwd;
  vfs_ref(new_process->cwd);

  // Fork the address space.
  new_process->page_directory = page_frame_alloc_directory();
  int result = vm_fork_address_space_into(new_process);
  if (result) {
    // TODO(aoates): clean up partial proc on failure.
    return result;
  }

  // Duplicate any signal handlers.  The set of pending signals in the child
  // is set to empty, however.
  for (int signo = APOS_SIGMIN; signo <= APOS_SIGMAX; ++signo) {
    new_process->signal_dispositions[signo] =
        proc_current()->signal_dispositions[signo];
  }

  // Don't duplicate the alarm; pending alarms are cleared in the child.

  // Propagate identity.
  new_process->ruid = proc_current()->ruid;
  new_process->rgid = proc_current()->rgid;
  new_process->euid = proc_current()->euid;
  new_process->egid = proc_current()->egid;
  new_process->suid = proc_current()->suid;
  new_process->sgid = proc_current()->sgid;

  new_process->umask = proc_current()->umask;

  new_process->pgroup = proc_current()->pgroup;
  list_push(&proc_group_get(new_process->pgroup)->procs,
            &new_process->pgroup_link);

  for (int i = 0; i < APOS_RLIMIT_NUM_RESOURCES; ++i) {
    new_process->limits[i] = proc_current()->limits[i];
  }

  // Create the kthread.
  proc_start_args_t* trampoline_args =
      (proc_start_args_t*)kmalloc(sizeof(proc_start_args_t));
  if (!trampoline_args) {
    // TODO(aoates): clean up partial proc on failure.
    return -ENOMEM;
  }

  trampoline_args->start = start;
  trampoline_args->arg = arg;

  kthread_t new_thread;
  result = kthread_create(&new_thread, &proc_fork_trampoline, trampoline_args);
  if (result) {
    // TODO(aoates): clean up partial proc on failure.
    kfree(trampoline_args);
    return result;
  }
  // TODO(aoates): move this into a middle layer of thread management.
  new_thread->process = new_process;
  list_push(&new_process->threads, &new_thread->proc_threads_link);
  kthread_detach(new_thread);

  scheduler_make_runnable(new_thread);

  new_process->parent = proc_current();
  list_push(&proc_current()->children_list,
            &new_process->children_link);

  new_process->state = PROC_RUNNING;
  return new_process->id;
}
