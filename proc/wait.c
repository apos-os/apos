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

#include "proc/wait.h"

#include "arch/memory/page_alloc.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "memory/vm.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/process-internal.h"
#include "proc/scheduler.h"
#include "user/include/apos/wait.h"

pid_t proc_wait(int* exit_status) {
  return proc_waitpid(-1, exit_status, 0);
}

// Returns true if the given process matches the pid (which has the semantics as
// for waitpid()'s pid argument).
static bool matches_pid(process_t* proc, pid_t wait_pid) {
  KASSERT_DBG(proc->parent == proc_current());
  return (wait_pid == -1 || wait_pid == proc->id || wait_pid == -proc->pgroup);
}

// Returns true if the given process is eligable for waiting with the given
// waitpid() flags.
static bool eligable_wait(process_t* proc, int options) {
  if (proc->state == PROC_ZOMBIE) {
    return true;
  } else if ((options & WUNTRACED) && proc->state == PROC_STOPPED &&
             WIFSTOPPED(proc->exit_status)) {
    return true;
  } else if ((options & WCONTINUED) && proc->state == PROC_RUNNING &&
             WIFCONTINUED(proc->exit_status)) {
    return true;
  }

  return false;
}

pid_t proc_waitpid(pid_t pid, int* exit_status, int options) {
  if ((options & ~WUNTRACED & ~WCONTINUED & ~WNOHANG) != 0) return -EINVAL;

  process_t* const p = proc_current();
  if (pid == 0) pid = -p->pgroup;

  // Look for an existing zombie child.
  process_t* zombie = 0x0;
  while (!zombie) {
    bool found_matching_child = false;
    list_link_t* child_link = p->children_list.head;
    while (child_link) {
      process_t* const child_process = container_of(child_link, process_t,
                                                    children_link);
      KASSERT(child_process->parent == p);
      if (matches_pid(child_process, pid)) {
        found_matching_child = true;
        if (eligable_wait(child_process, options)) {
          zombie = child_process;
          break;
        }
      }
      child_link = child_link->next;
    }

    if (!found_matching_child) {
      return -ECHILD;
    }

    // If we didn't find one, wait for a child to exit and wake us up.
    if (!zombie) {
      if (options & WNOHANG)
        return 0;

      int wait_result = scheduler_wait_on_interruptable(&p->wait_queue, -1);
      if (wait_result == SWAIT_INTERRUPTED)
        return -EINTR;
    }
  }

  if (zombie->state == PROC_STOPPED) {
    KASSERT_DBG(options & WUNTRACED);
    if (exit_status)
      *exit_status = zombie->exit_status;
    zombie->exit_status = 0;
    return zombie->id;
  }

  if (zombie->state == PROC_RUNNING) {
    KASSERT_DBG(options & WCONTINUED);
    KASSERT_DBG(WIFCONTINUED(zombie->exit_status));
    if (exit_status)
      *exit_status = zombie->exit_status;
    zombie->exit_status = 0;
    return zombie->id;
  }

  KASSERT(zombie->state == PROC_ZOMBIE);
  list_remove(&p->children_list, &zombie->children_link);

  // Tear down the child's address space.
  // Destroy all VM areas.
  list_link_t* vm_link = list_pop(&zombie->vm_area_list);
  while (vm_link) {
    vm_area_t* const area = container_of(vm_link, vm_area_t, vm_proc_list);
    vm_area_destroy(area);
    vm_link = list_pop(&zombie->vm_area_list);
  }

  page_frame_free_directory(zombie->page_directory);
  zombie->page_directory = 0x0;

  // Copy its exit status and destroy the process_t.
  zombie->state = PROC_INVALID;
  KASSERT(zombie->thread == KTHREAD_NO_THREAD);
  if (exit_status) {
    *exit_status = zombie->exit_status;
  }
  pid_t zombie_pid = zombie->id;
  proc_destroy(zombie);
  return zombie_pid;
}
