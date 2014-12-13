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

#include "common/errno.h"
#include "common/kassert.h"
#include "proc/exit.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "vfs/vfs.h"

void proc_exit(int status) {
  KASSERT(kthread_current_thread() == proc_current()->thread);
  KASSERT(proc_current()->state == PROC_RUNNING);

  process_t* const p = proc_current();

  if (p->id == 0) {
    die("Cannot exit() the root thread");
  }

  p->exit_status = status;

  // Close all open fds.
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (p->fds[i] >= 0) {
      int result = vfs_close(i);
      if (result) {
        klogfm(KL_PROC, WARNING, "unable to close fd %d in proc_exit(): %s\n",
               i, errorname(-result));
      }
    }
  }

  if (p->cwd) {
    vfs_put(p->cwd);
    p->cwd = 0x0;
  }

  // Note: the vm_area_t list is torn down in the parent in proc_wait, NOT here.

  // Cancel any outstanding alarms.
  proc_alarm(0);

  // Remove it from the process group list.
  list_remove(proc_group_get(p->pgroup), &p->pgroup_link);
  p->pgroup = -1;

  // Move any pending children to the root process.
  process_t* const root_process = proc_get(0);
  list_link_t* child_link = list_pop(&p->children_list);
  while (child_link) {
    process_t* const child_process = container_of(child_link, process_t,
                                                  children_link);
    KASSERT(child_process->parent == p);
    child_process->parent = root_process;
    list_push(&root_process->children_list, &child_process->children_link);
    child_link = list_pop(&p->children_list);
  }

  p->state = PROC_ZOMBIE;
  p->thread = KTHREAD_NO_THREAD;

  // Send SIGCHLD to the parent.
  KASSERT(proc_force_signal(p->parent, SIGCHLD) == 0);

  // Wake up parent if it's wait()'ing.
  scheduler_wake_one(&p->parent->wait_queue);

  kthread_exit(0x0);
  die("unreachable");
}
