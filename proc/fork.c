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
#include "common/atomic.h"
#include "common/kassert.h"
#include "common/errno.h"
#include "memory/kmalloc.h"
#include "memory/vm.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/pmutex.h"
#include "proc/process.h"
#include "proc/process-internal.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
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
  atomic_flag_set(&g_forked);
  process_t* new_process = proc_alloc();
  if (!new_process) return -ENOMEM;

  process_t* const parent = proc_current();
  new_process->user_arch = parent->user_arch;

  // Fork VFS handles.
  pmutex_lock(&parent->mu);
  vfs_fork_fds(parent, new_process);
  new_process->cwd = parent->cwd;
  vfs_ref(new_process->cwd);

  new_process->umask = parent->umask;

  // Fork the address space.
  new_process->page_directory = page_frame_alloc_directory();
  int result = vm_fork_address_space_into(parent, new_process);
  pmutex_unlock(&parent->mu);
  if (result) {
    // TODO(aoates): clean up partial proc on failure.
    return result;
  }

  // Duplicate any signal handlers.  The set of pending signals in the child
  // is set to empty, however.
  kspin_constructor(&new_process->spin_mu);
  for (int signo = APOS_SIGMIN; signo <= APOS_SIGMAX; ++signo) {
    new_process->signal_dispositions[signo] =
        parent->signal_dispositions[signo];
  }

  // Don't duplicate the alarm; pending alarms are cleared in the child.

  // Propagate identity.
  kspin_lock(&g_proc_table_lock);
  new_process->ruid = parent->ruid;
  new_process->rgid = parent->rgid;
  new_process->euid = parent->euid;
  new_process->egid = parent->egid;
  new_process->suid = parent->suid;
  new_process->sgid = parent->sgid;
  kspin_unlock(&g_proc_table_lock);

  for (int i = 0; i < APOS_RLIMIT_NUM_RESOURCES; ++i) {
    new_process->limits[i] = parent->limits[i];
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

  new_process->state = PROC_RUNNING;

  // Make the child visible via the parent's children_list and process group.
  pmutex_lock(&parent->mu);
  new_process->parent = parent;
  list_push(&parent->children_list,
            &new_process->children_link);

  kspin_lock(&g_proc_table_lock);
  new_process->pgroup = parent->pgroup;
  proc_group_add(proc_group_get(new_process->pgroup), new_process);
  kspin_unlock(&g_proc_table_lock);
  pmutex_unlock(&parent->mu);

  scheduler_make_runnable(new_thread);

  return new_process->id;
}
