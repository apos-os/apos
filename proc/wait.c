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

#include "arch/memory/page_map.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "memory/vm.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "proc/spinlock.h"
#include "user/include/apos/wait.h"

kpid_t proc_wait(int* exit_status) {
  return proc_waitpid(-1, exit_status, 0);
}

// Returns true if the given process matches the pid (which has the semantics as
// for waitpid()'s pid argument).
static bool matches_pid(process_t* proc, kpid_t wait_pid)
    REQUIRES(g_proc_table_lock) {
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

// Once an eligable child has been found, this finishes the call to waitpid()
// (cleaning up the child if necessary, setting output parameters, etc).
static kpid_t finish_waitpid(process_t* zombie, int* exit_status, int options)
    RELEASE(g_proc_table_lock);

kpid_t proc_waitpid(kpid_t pid, int* exit_status, int options) {
  if ((options & ~WUNTRACED & ~WCONTINUED & ~WNOHANG) != 0) return -EINVAL;

  process_t* const p = proc_current();

  // Look for an existing zombie child.
  process_t* zombie = 0x0;
  while (true) {
    kspin_lock(&g_proc_table_lock);
    // We re-check the current pgroup each time we sleep, in case it changes.
    kpid_t search_pid = (pid == 0) ? -p->pgroup : pid;
    bool found_matching_child = false;
    list_link_t* child_link = p->children_list.head;
    while (child_link) {
      process_t* const child_process = container_of(child_link, process_t,
                                                    children_link);
      KASSERT(child_process->parent == p);
      if (matches_pid(child_process, search_pid)) {
        found_matching_child = true;
        if (eligable_wait(child_process, options)) {
          return finish_waitpid(child_process, exit_status, options);
        }
      }
      child_link = child_link->next;
    }
    kspin_unlock(&g_proc_table_lock);

    if (!found_matching_child) {
      return -ECHILD;
    }

    // If we didn't find one, wait for a child to exit and wake us up.
    KASSERT(!zombie);
    if (options & WNOHANG)
      return 0;

    int wait_result = scheduler_wait_on_interruptable(&p->wait_queue, -1);
    if (wait_result == SWAIT_INTERRUPTED)
      return -EINTR;
  }
  die("unreachable");
}

static kpid_t finish_waitpid(process_t* zombie, int* exit_status, int options) {
  kspin_assert_is_held(&g_proc_table_lock);

  process_t* const p = proc_current();
  KASSERT_DBG(zombie->parent == p);

  if (zombie->state == PROC_STOPPED) {
    KASSERT_DBG(options & WUNTRACED);
    if (exit_status)
      *exit_status = zombie->exit_status;
    zombie->exit_status = 0;
    kspin_unlock(&g_proc_table_lock);
    return zombie->id;
  }

  if (zombie->state == PROC_RUNNING) {
    KASSERT_DBG(options & WCONTINUED);
    KASSERT_DBG(WIFCONTINUED(zombie->exit_status));
    if (exit_status)
      *exit_status = zombie->exit_status;
    zombie->exit_status = 0;
    kspin_unlock(&g_proc_table_lock);
    return zombie->id;
  }

  KASSERT(zombie->state == PROC_ZOMBIE);

  // Remove it from the process group list.
  proc_group_remove(proc_group_get(zombie->pgroup), zombie);
  kspin_unlock(&g_proc_table_lock);

  list_remove(&p->children_list, &zombie->children_link);
  zombie->parent = NULL;

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
  if (exit_status) {
    *exit_status = zombie->exit_status;
  }
  kpid_t zombie_pid = zombie->id;
  proc_put(zombie);  // Will destroy if no other references.
  return zombie_pid;
}

uint32_t proc_get_procguid(kpid_t pid) {
  process_t* proc = proc_get(pid);
  // If the caller is racey with the process exiting, this might catch it.
  KASSERT(proc != NULL);
  return proc->guid;
}

int proc_wait_guid(kpid_t pid, uint32_t guid, int timeout_ms) {
  const apos_ms_t start = get_time_ms();
  do {
    process_t* proc = proc_get(pid);
    // If it exited or another started, success.
    if (!proc || proc->guid != guid) {
      return 0;
    }
    ksleep(20);
  } while (get_time_ms() < start + timeout_ms);
  return -ETIMEDOUT;
}
