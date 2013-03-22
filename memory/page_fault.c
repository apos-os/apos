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

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "dev/interrupts.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/page_fault.h"
#include "memory/page_alloc.h"

// TODO(aoates): define these common interrupts in dev/interrupts.h
#define PAGE_FAULT_INTERRUPT 0x0E

static memory_info_t* g_meminfo = 0;

void paging_init(memory_info_t* meminfo) {
  g_meminfo = meminfo;
  register_interrupt_handler(PAGE_FAULT_INTERRUPT, &page_fault_handler);
}

void page_fault_handler(uint32_t interrupt, uint32_t error) {
  KASSERT(interrupt == PAGE_FAULT_INTERRUPT);

  uint32_t address;
  asm volatile ("movl %%cr2, %0\n\t" : "=r"(address));

  //klogf("page fault: addr: 0x%x  error: 0x%x\n", address, error);

  if (address >= g_meminfo->heap_start && address < g_meminfo->heap_end) {
    // TODO(aoates): properly handle user-mode processes trying to access the
    // kernel heap.
    KASSERT((error & 0x04) == 0);

    // Get a new physical page and map it in.
    const uint32_t phys_addr = page_frame_alloc();
    KASSERT(phys_addr);
    const uint32_t virt_addr = addr2page(address);
    //klogf("  page fault: mapping 0x%x --> 0x%x\n", virt_addr, phys_addr);
    page_frame_map_virtual(virt_addr, phys_addr,
                           MEM_PROT_ALL,
                           MEM_ACCESS_KERNEL_ONLY,
                           MEM_GLOBAL);
    return;
  }

  klogf("kernel page fault: addr: 0x%x  error: 0x%x\n", address, error);
  die("unhandled kernel page fault");
}
