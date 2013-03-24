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
#include "common/list.h"
#include "memory/vm.h"
#include "memory/vm_area.h"

void vm_insert_area(process_t* proc, vm_area_t* area) {
  KASSERT(!list_link_on_list(&proc->vm_area_list, &area->vm_proc_list));
  list_link_t* prev = 0x0;
  list_link_t* curr = proc->vm_area_list.head;
  while (curr) {
    vm_area_t* curr_area = container_of(curr, vm_area_t, vm_proc_list);
    if (curr_area->vm_base > area->vm_base) {
      KASSERT(area->vm_base + area->vm_length <= curr_area->vm_base);
      break;
    }
    prev = curr;
    curr = curr->next;
  }
  if (prev) {
    vm_area_t* prev_area = container_of(prev, vm_area_t, vm_proc_list);
    KASSERT(prev_area->vm_base + prev_area->vm_length <= area->vm_base);
  }
  list_insert(&proc->vm_area_list, prev, &area->vm_proc_list);
}
