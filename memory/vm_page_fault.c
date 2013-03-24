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
#include "common/klog.h"
#include "common/list.h"
#include "common/types.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/vm_page_fault.h"
#include "memory/vm_area.h"
#include "proc/process.h"

static inline vm_area_t* link2area(list_link_t* link) {
  return container_of(link, vm_area_t, vm_proc_list);
}

static void check_vm_list(process_t* proc) {
  list_link_t* link = proc->vm_area_list.head;
  while (link) {
    vm_area_t* const area = link2area(link);
    KASSERT(area->vm_base >= MEM_FIRST_MAPPABLE_ADDR);
    KASSERT(area->vm_length > 0);
    KASSERT(MEM_LAST_MAPPABLE_ADDR - area->vm_base >= area->vm_length);
    KASSERT(area->vm_base % PAGE_SIZE == 0);
    KASSERT(area->vm_length % PAGE_SIZE == 0);
    KASSERT(area->memobj_base % PAGE_SIZE == 0);
    if (link->prev) {
      vm_area_t* const prev_area = link2area(link->prev);
      KASSERT(area->vm_base > prev_area->vm_base);
      KASSERT(area->vm_base >= prev_area->vm_base + prev_area->vm_length);
    }
    link = link->next;
  }
}

static vm_area_t* find_area(process_t* proc, addr_t address) {
  list_link_t* link = proc->vm_area_list.head;
  while (link) {
    vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    if (address >= area->vm_base && address < area->vm_base + area->vm_length) {
      return area;
    }
    link = link->next;
  }
  return 0x0;
}

void vm_handle_page_fault(addr_t address, vm_fault_type_t type,
                          vm_fault_op_t op, vm_fault_mode_t mode) {
  // TODO(aoates): properly handle user-mode processes trying to access the
  // kernel heap.
  KASSERT(type == VM_FAULT_NOT_PRESENT);
  KASSERT(mode == VM_FAULT_KERNEL);

  process_t* proc = proc_current();
  if (ENABLE_KERNEL_SAFETY_NETS) {
    check_vm_list(proc);
  }

  // Find the vm_area containing the address.
  vm_area_t* area = find_area(proc, address);
  if (area) {
    KASSERT(!area->memobj);
    // Get a new physical page and map it in.
    const uint32_t phys_addr = page_frame_alloc();
    KASSERT(phys_addr);
    const uint32_t virt_addr = addr2page(address);
    page_frame_map_virtual(virt_addr, phys_addr,
                           MEM_PROT_ALL,
                           MEM_ACCESS_KERNEL_ONLY,
                           MEM_GLOBAL);
  } else {
    if (mode == VM_FAULT_KERNEL) {
      klogf("kernel page fault: addr: 0x%x\n", address);
      die("unhandled kernel page fault");
    } else {
      // TODO(aoates): handle user-mode segfaults.
      die("user mode page fault (unsupported)");
    }
  }
}
