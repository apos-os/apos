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
#include "common/list.h"
#include "common/math.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/process.h"

addr_t vm_find_hole(process_t* proc, addr_t start_addr, addr_t end_addr,
                    addr_t length) {
  addr_t addr = start_addr;
  list_link_t* link = proc->vm_area_list.head;
  while (link && addr < end_addr) {
    const vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    if (addr < area->vm_base) {
      const addr_t hole_size = min(area->vm_base, end_addr) - addr;
      if (hole_size >= length) {
        return addr;
      }
    }
    addr = area->vm_base + area->vm_length;
    link = link->next;
  }

  if (addr >= end_addr || (end_addr - addr) < length) {
    return 0;
  } else {
    return addr;
  }
}

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

int vm_verify_region(process_t* proc, addr_t start, addr_t end,
                     int is_write, int is_user) {
  if (!proc || start >= end) {
    return -EINVAL;
  }

  list_link_t* link = proc->vm_area_list.head;
  while (link && start < end) {
    vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    const addr_t overlap_start = max(area->vm_base, start);
    const addr_t overlap_end =
        max(overlap_start, min(area->vm_base + area->vm_length, end));
    if (area->vm_base > end) {
      break;
    } else if (area->vm_base > start) {
      return -EFAULT;
    } else if (overlap_start < overlap_end) {
      if (is_write && (!(area->prot & MEM_PROT_WRITE)))
        return -EFAULT;
      if (is_user && (area->access != MEM_ACCESS_KERNEL_AND_USER))
        return -EFAULT;
    }
    start = overlap_end;
    link = link->next;
  }

  if (start < end) {
    return -EFAULT;
  } else {
    return 0;
  }
}
