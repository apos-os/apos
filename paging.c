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

#include "kassert.h"
#include "paging.h"

#define PAGE_SIZE          0x00001000

#define PDE_ADDRESS_MASK   0xFFFFF000
#define PDE_LARGE_PAGES    0x00000080
#define PDE_ACCESSED       0x00000020
#define PDE_CACHE_DISABLED 0x00000010
#define PDE_WRITE_THROUGH  0x00000008
#define PDE_USER_ACCESS    0x00000004
#define PDE_WRITABLE       0x00000002
#define PDE_PRESENT        0x00000001
#define PDE_NUM_ENTRIES    PAGE_SIZE / 4

#define PTE_ADDRESS_MASK   0xFFFFF000
#define PTE_GLOBAL         0x00000100
#define PTE_DIRTY          0x00000040
#define PTE_ACCESSED       0x00000020
#define PTE_CACHE_DISABLED 0x00000010
#define PTE_WRITE_TRHOUGH  0x00000008
#define PTE_USER_ACCESS    0x00000004
#define PTE_WRITABLE       0x00000002
#define PTE_PRESENT        0x00000001
#define PTE_NUM_ENTRIES    PAGE_SIZE / 4

// Memory limits of the kernel --- symbols defined at the start and end of the
// kernel.  Defined in loader.s.
extern uint32_t KERNEL_START_SYMBOL;
extern uint32_t KERNEL_END_SYMBOL;

uint32_t* page_directory = 0;

void paging_init() {
  // First, find a spot just past the end of the kernel to put our initial PDE.
  // Find the final page, then add one to get the next whole page after the end
  // of the kernel.
  page_directory = (uint32_t*)(
      ((uint32_t)(&KERNEL_END_SYMBOL) & PDE_ADDRESS_MASK) + PAGE_SIZE);

  // Zero it out.
  int i;
  for (i = 0; i < PDE_NUM_ENTRIES; ++i) {
    // 4kb, supervisor-only, non-present, read/write pages.
    page_directory[i] = 0 | PDE_WRITABLE;
  }

  // Create an initial PTE as well.  Identity map the first 4MB.
  uint32_t* page_table = (uint32_t*)((uint32_t)page_directory + PAGE_SIZE);
  for (i = 0; i < PTE_NUM_ENTRIES; ++i) {
    const uint32_t address = i * PAGE_SIZE;
    page_table[i] = (address & PTE_ADDRESS_MASK) | PTE_WRITABLE | PTE_PRESENT;
  }
  kassert(i * PAGE_SIZE > (uint32_t)page_table + PAGE_SIZE);

  // Install the PTE.
  page_directory[0] =
      ((uint32_t)page_table & PDE_ADDRESS_MASK) | PDE_WRITABLE | PDE_PRESENT;

  // Install the PDE and enable paging.
  __asm__ __volatile__
      ("mov %0, %%cr3;"
       "mov %%cr0, %%eax;"
       "or 0x80000000, %%eax;"
       "mov %%eax, %%cr0"
       :: "b"(page_directory) : "eax");
}
