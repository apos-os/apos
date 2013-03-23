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
#include "common/types.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/vm_page_fault.h"

void vm_handle_page_fault(addr_t address, vm_fault_type_t type,
                          vm_fault_op_t op, vm_fault_mode_t mode) {
  // TODO(aoates): properly handle user-mode processes trying to access the
  // kernel heap.
  KASSERT(type == VM_FAULT_NOT_PRESENT);
  KASSERT(mode == VM_FAULT_KERNEL);

  const memory_info_t* meminfo = get_global_meminfo();

  if (address >= meminfo->heap_start && address < meminfo->heap_end) {
    // Get a new physical page and map it in.
    const uint32_t phys_addr = page_frame_alloc();
    KASSERT(phys_addr);
    const uint32_t virt_addr = addr2page(address);
    page_frame_map_virtual(virt_addr, phys_addr,
                           MEM_PROT_ALL,
                           MEM_ACCESS_KERNEL_ONLY,
                           MEM_GLOBAL);
    return;
  }

  klogf("kernel page fault: addr: 0x%x\n", address);
  die("unhandled kernel page fault");
}
