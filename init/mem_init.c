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

#include "init/mem_init.h"

#define PAGE_SIZE          0x00001000
#define PAGE_INDEX_MASK    0xFFFFF000
#define PAGE_OFFSET_MASK   0x00000FFF

#define PDE_ADDRESS_MASK   0xFFFFF000 /* PAGE_INDEX_MASK */
#define PDE_LARGE_PAGES    0x00000080
#define PDE_ACCESSED       0x00000020
#define PDE_CACHE_DISABLED 0x00000010
#define PDE_WRITE_THROUGH  0x00000008
#define PDE_USER_ACCESS    0x00000004
#define PDE_WRITABLE       0x00000002
#define PDE_PRESENT        0x00000001
#define PDE_NUM_ENTRIES    (PAGE_SIZE / 4)

#define PTE_ADDRESS_MASK   0xFFFFF000 /* PAGE_INDEX_MASK */
#define PTE_GLOBAL         0x00000100
#define PTE_DIRTY          0x00000040
#define PTE_ACCESSED       0x00000020
#define PTE_CACHE_DISABLED 0x00000010
#define PTE_WRITE_TRHOUGH  0x00000008
#define PTE_USER_ACCESS    0x00000004
#define PTE_WRITABLE       0x00000002
#define PTE_PRESENT        0x00000001
#define PTE_NUM_ENTRIES    (PAGE_SIZE / 4)

// Memory limits of the kernel --- symbols defined at the start and end of the
// kernel.  Defined in loader.s.
//
// Note: these are the VIRTUAL addresses of the start and end.
extern uint32_t KERNEL_START_SYMBOL;
extern uint32_t KERNEL_END_SYMBOL;

// The VMA offset at which we're loading our kernel.  We can subtract this from
// KERNEL_{START,END}_SYMBOL to get the physical limits of the kernel as loaded
// by GRUB.
//
// Note: keep this is sync with the constant in linker.ld.
const uint32_t KERNEL_VIRT_START = 0xC0000000;

uint32_t* page_directory = 0;

static void die_phys() {
  __asm__("int $3");
}

// We have to use our own version of kassert, since the normal kassert is linked
// in virtual memory.
static void kassert_phys(int x) {
  if (!x) {
    die_phys();
  }
}

// Assert that the given value is page-aligned.
static void kassert_page_aligned(uint32_t x) {
  kassert_phys((x & PAGE_OFFSET_MASK) == 0);
}

// Fill the given page table with a linear mapping from virt_base to phys_base.
// Then install the page table in the given PDE.
// virt_base must be PTE-size aligned (that is, must be 4MB aligned if each PTE
// represents 4MB).
static void map_linear_page_table(uint32_t* pde, uint32_t* pte,
                                  uint32_t virt_base, uint32_t phys_base) {
  // Ensure everything is page-aligned.
  kassert_page_aligned(pde);
  kassert_page_aligned(pte);
  kassert_page_aligned(virt_base);
  kassert_page_aligned(virt_base / PAGE_SIZE);
  kassert_page_aligned(phys_base);

  for (int i = 0; i < PTE_NUM_ENTRIES; ++i) {
    const uint32_t phys_address = phys_base + i * PAGE_SIZE;
    pte[i] = (phys_address & PTE_ADDRESS_MASK) | PTE_WRITABLE | PTE_PRESENT;
  }

  // Install the PTE.
  const int virt_page_idx = virt_base / PAGE_SIZE;
  const int pde_idx = virt_page_idx / PDE_NUM_ENTRIES;
  pde[pde_idx] = ((uint32_t)pte & PDE_ADDRESS_MASK) | PDE_WRITABLE | PDE_PRESENT;
}

void paging_init() {
  // First, find a spot just past the end of the kernel to put our initial PDE.
  // Find the final page, then add one to get the next whole page after the end
  // of the kernel.
  const uint32_t phys_kernel_end = (uint32_t)(&KERNEL_END_SYMBOL) - KERNEL_VIRT_START;
  page_directory = (uint32_t*)((phys_kernel_end & PDE_ADDRESS_MASK) + PAGE_SIZE);

  // Zero it out.
  uint32_t i;
  for (i = 0; i < PDE_NUM_ENTRIES; ++i) {
    // 4kb, supervisor-only, non-present, read/write pages.
    page_directory[i] = 0 | PDE_WRITABLE;
  }

  // Create two initial PTEs as well.  Identity map the first 4MB, and map the
  // higher-half kernel to the first physical 4MB as well.
  uint32_t* page_table1 = (uint32_t*)((uint32_t)page_directory + PAGE_SIZE);
  map_linear_page_table(page_directory, page_table1, 0x0, 0x0);
  uint32_t* page_table2 = (uint32_t*)((uint32_t)page_table1 + PAGE_SIZE);
  map_linear_page_table(page_directory, page_table2, KERNEL_VIRT_START, 0x0);

  // Install the PDE and enable paging.
  __asm__ __volatile__
      ("mov %0, %%cr3;"
       "mov %%cr0, %%eax;"
       "or 0x80000000, %%eax;"
       "mov %%eax, %%cr0"
       :: "b"(page_directory) : "eax");
}
