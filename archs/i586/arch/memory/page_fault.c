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

#include "arch/memory/page_alloc.h"
#include "arch/memory/page_fault.h"
#include "archs/i586/internal/dev/interrupts-x86.h"
#include "archs/i586/internal/memory/page_fault-x86.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/vm_page_fault.h"

// TODO(aoates): define these common interrupts in dev/interrupts.h
#define PAGE_FAULT_INTERRUPT 0x0E

#define PAGE_FAULT_ERR_PRESENT 0x01
#define PAGE_FAULT_ERR_WRITE   0x02
#define PAGE_FAULT_ERR_USER    0x04
#define PAGE_FAULT_ERR_RSVD    0x08

static memory_info_t* g_meminfo = 0;

void paging_init(memory_info_t* meminfo) {
  g_meminfo = meminfo;
  register_interrupt_handler(PAGE_FAULT_INTERRUPT, &page_fault_handler);
}

void page_fault_handler(uint32_t interrupt, uint32_t error, bool is_user) {
  KASSERT(interrupt == PAGE_FAULT_INTERRUPT);
  KASSERT((error & PAGE_FAULT_ERR_RSVD) == 0);

  _Static_assert(sizeof(addr_t) == sizeof(uint32_t), "Not 32-bit");
  addr_t address;
  asm volatile ("movl %%cr2, %0\n\t" : "=r"(address));

  const vm_fault_type_t type =
      (error & PAGE_FAULT_ERR_PRESENT) ? VM_FAULT_ACCESS : VM_FAULT_NOT_PRESENT;
  const vm_fault_op_t op =
      (error & PAGE_FAULT_ERR_WRITE) ? VM_FAULT_WRITE : VM_FAULT_READ;
  const vm_fault_mode_t mode =
      (error & PAGE_FAULT_ERR_USER) ? VM_FAULT_USER : VM_FAULT_KERNEL;
  KASSERT_DBG(is_user ? (mode == VM_FAULT_USER) : (mode == VM_FAULT_KERNEL));

  // Ignore return value --- if it failed, a signal was generated and will be
  // dispatched as needed.
  vm_handle_page_fault(address, type, op, mode);
}
