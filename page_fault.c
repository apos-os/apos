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
#include "page_fault.h"

// TODO(aoates): define these common interrupts in dev/interrupts.h
#define PAGE_FAULT_INTERRUPT 0x0E

void paging_init() {
  register_interrupt_handler(PAGE_FAULT_INTERRUPT, &page_fault_handler);
}

void page_fault_handler(uint32_t interrupt, uint32_t error) {
  KASSERT(interrupt == PAGE_FAULT_INTERRUPT);

  uint32_t address;
  __asm__ __volatile__ ("movl %%cr2, %0\n\t" : "=g"(address));

  klogf("page fault: addr: 0x%x  error: 0x%x\n", address, error);
  die("unhandled kernel page fault");
}
