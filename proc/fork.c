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

#include "common/kassert.h"
#include "common/errno.h"
#include "memory/kmalloc.h"
#include "memory/page_alloc.h"
#include "memory/vm.h"
#include "proc/exit.h"
#include "proc/fork.h"
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

  // Create the kthread.
  proc_start_args_t* trampoline_args =
      (proc_start_args_t*)kmalloc(sizeof(proc_start_args_t));
  if (!trampoline_args) {
    // TODO(aoates): clean up partial proc on failure.
    return -ENOMEM;
  }

  trampoline_args->start = start;
  trampoline_args->arg = arg;

  result = kthread_create(&new_process->thread, &proc_fork_trampoline,
                              trampoline_args);
  if (result) {
    // TODO(aoates): clean up partial proc on failure.
    kfree(trampoline_args);
    return result;
  }
  new_process->thread->process = new_process;
  kthread_detach(new_process->thread);

  scheduler_make_runnable(new_process->thread);

  new_process->parent = proc_current();
  list_push(&proc_current()->children_list,
            &new_process->children_link);

  new_process->state = PROC_RUNNING;
  return new_process->id;
}
