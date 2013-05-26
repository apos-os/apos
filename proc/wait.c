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
#include "memory/page_alloc.h"
#include "memory/vm.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/process-internal.h"
#include "proc/scheduler.h"

pid_t proc_wait(int* exit_status) {
  process_t* const p = proc_current();

  // Look for an existing zombie child.
  process_t* zombie = 0x0;
  while (!zombie) {
    list_link_t* child_link = p->children_list.head;
    while (child_link) {
      process_t* const child_process = container_of(child_link, process_t,
                                                    children_link);
      KASSERT(child_process->parent == p);
      if (child_process->state == PROC_ZOMBIE) {
        zombie = child_process;
        break;
      }
      child_link = child_link->next;
    }

    // If we didn't find one, wait for a child to exit and wake us up.
    if (!zombie) {
      scheduler_wait_on(&p->wait_queue);
    }
  }

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
