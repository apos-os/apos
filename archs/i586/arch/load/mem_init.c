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

#include "arch/load/mem_init.h"
#include "memory/memory.h"

// Memory limits of the kernel --- symbols defined at the start and end of the
// kernel.  Defined in loader.s.
//
// Note: these are the VIRTUAL addresses of the start and end.
extern uint32_t KERNEL_START_SYMBOL;
extern uint32_t KERNEL_END_SYMBOL;

// We will additionally set up a linear map for physical memory into the
// kernel's virtual memory space, starting at the following address.
const uint32_t KERNEL_PHYS_MAP_START = 0xE0000000;

// The maximum number of bytes we'll physically map into the region starting at
// KERNEL_PHYS_MAP_START.
const uint32_t KERNEL_PHYS_MAP_MAX_LENGTH = 0x10000000;

// The maximum amount of physical memory we support (due to the
// KERNEL_PHYS_MAP_START).
// TODO(aoates): add option to page allocator to allocate only from
// physically-mapped region, then remove this artificial cap.
const uint32_t MAX_MEMORY_BYTES = 0x10000000;

// The virtual start and end addresses of the kernel heap.
const uint32_t START_HEAP = 0xD0000000;
const uint32_t END_HEAP =   0xE0000000;

static void die_phys(void) {
  asm("int $3");
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

// Allocate an (aligned) page at the end of the current kernel physical space,
// updating meminfo->kernel_end_phys as necessary.
static uint32_t* kalloc_page(memory_info_t* meminfo) {
  uint32_t* addr = (uint32_t*)0xDEADBEEF;
  if ((meminfo->kernel_end_phys & PAGE_OFFSET_MASK) == 0) {
    addr = (uint32_t*)meminfo->kernel_end_phys;
  } else {
    addr = (uint32_t*)(
        (meminfo->kernel_end_phys & PAGE_INDEX_MASK) + PAGE_SIZE);
  }
  meminfo->kernel_end_phys = (uint32_t)addr + PAGE_SIZE;
  return addr;
}

// Fill the given page table with a linear mapping from virt_base to phys_base.
// Then install the page table in the given PDE.
// virt_base must be PTE-size aligned (that is, must be 4MB aligned if each PTE
// represents 4MB).
static void map_linear_page_table(uint32_t* pde, uint32_t* pte,
                                  uint32_t virt_base, uint32_t phys_base) {
  // Ensure everything is page-aligned.
  kassert_page_aligned((uint32_t)pde);
  kassert_page_aligned((uint32_t)pte);
  kassert_page_aligned(virt_base);
  kassert_page_aligned(phys_base);
  kassert_phys((virt_base % (PAGE_SIZE * PDE_NUM_ENTRIES)) == 0);

  for (int i = 0; i < PTE_NUM_ENTRIES; ++i) {
    const uint32_t phys_address = phys_base + i * PAGE_SIZE;
    pte[i] = (phys_address & PTE_ADDRESS_MASK) | PTE_WRITABLE | PTE_PRESENT;
  }

  // Install the PTE.
  const int virt_page_idx = virt_base / PAGE_SIZE;
  const int pde_idx = virt_page_idx / PDE_NUM_ENTRIES;
  pde[pde_idx] = ((uint32_t)pte & PDE_ADDRESS_MASK) | PDE_WRITABLE | PDE_PRESENT;
}

// Set up page tables and enable paging.  Updates meminfo as it allocates and
// creates a virtual memory space.  Returns the new (virtual) address of
// meminfo.
static memory_info_t* setup_paging(memory_info_t* meminfo) {
  // First, find a spot just past the end of the kernel to put our initial PDE.
  // Find the final page, then add one to get the next whole page after the end
  // of the kernel.
  uint32_t* page_directory = kalloc_page(meminfo);

  // Zero it out.
  uint32_t i;
  for (i = 0; i < PDE_NUM_ENTRIES; ++i) {
    // 4kb, supervisor-only, non-present, read/write pages.
    page_directory[i] = 0 | PDE_WRITABLE;
  }

  // Create two initial PTEs as well.  Identity map the first 4MB, and map the
  // higher-half kernel to the first physical 4MB as well.
  // Note: Keep this in sync with load/kernel_init.c (which undoes the first
  // mapping).
  uint32_t* page_table1 = kalloc_page(meminfo);
  map_linear_page_table(page_directory, page_table1, 0x0, 0x0);
  uint32_t* page_table2 = kalloc_page(meminfo);
  map_linear_page_table(page_directory, page_table2, KERNEL_VIRT_START, 0x0);

  // Identity map the first KERNEL_PHYS_MAP_MAX_LENGTH bytes of physical memory
  // as well.
  uint32_t phys_map_len = meminfo->lower_memory + meminfo->upper_memory;
  if (phys_map_len > KERNEL_PHYS_MAP_MAX_LENGTH) {
    phys_map_len = KERNEL_PHYS_MAP_MAX_LENGTH;
  }
  uint32_t ident_addr = 0;
  while (ident_addr < phys_map_len) {
    uint32_t* ident_page_table = kalloc_page(meminfo);
    map_linear_page_table(page_directory, ident_page_table,
                          ident_addr + KERNEL_PHYS_MAP_START, ident_addr);
    ident_addr += PTE_NUM_ENTRIES * PAGE_SIZE;
  }
  meminfo->phys_map_length = phys_map_len;

  // Finally, map the last PDE entry onto itself so we can always access the
  // current PDE/PTEs without having to map them in explicitly.
  kassert_page_aligned((uint32_t)page_directory);
  page_directory[PDE_NUM_ENTRIES - 1] =
      (uint32_t)page_directory | PDE_WRITABLE | PDE_PRESENT;

  // Update meminfo.
  meminfo->kernel_start_virt = meminfo->kernel_start_phys + KERNEL_VIRT_START;
  meminfo->kernel_end_virt = meminfo->kernel_end_phys + KERNEL_VIRT_START;
  meminfo->mapped_start = KERNEL_VIRT_START;
  // We mapped a single PTE (4MB) for use by the kernel.
  meminfo->mapped_end = KERNEL_VIRT_START + PTE_NUM_ENTRIES * PAGE_SIZE;
  meminfo->kernel_page_directory = (page_dir_ptr_t)page_directory;

  // Install the PDE and enable paging.
  asm volatile
      ("mov %0, %%cr3;"
       "mov %%cr0, %%eax;"
       "or $0x80010000, %%eax;"
       "mov %%eax, %%cr0"
       :: "b"(page_directory) : "eax");

  // Return the virtual-mapped address of meminfo.
  return (memory_info_t*)(((uint32_t)meminfo) + KERNEL_VIRT_START);
}

// Allocates a memory_info_t at the end of the kernel and fills it in with what
// we know.
static memory_info_t* create_initial_meminfo(multiboot_info_t* mb_info,
                                             uint32_t stack) {
  // Statically allocate a memory_info_t.  We will pass this around to keep
  // track of how much memory we allocate here, updating
  // meminfo->kernel_end_{phys, virt} as needed.
  static memory_info_t g_meminfo;

  g_meminfo.kernel_start_phys =
      (uint32_t)(&KERNEL_START_SYMBOL) - KERNEL_VIRT_START;
  // Account for the memory_info_t we just allocated.
  g_meminfo.kernel_end_phys =
      (uint32_t)(&KERNEL_END_SYMBOL) - KERNEL_VIRT_START;

  g_meminfo.kernel_start_virt = g_meminfo.kernel_end_virt = 0;
  g_meminfo.mapped_start = g_meminfo.mapped_end = 0;

  kassert_phys((mb_info->flags & MULTIBOOT_INFO_MEMORY) != 0);
  g_meminfo.lower_memory = mb_info->mem_lower * 1024;
  g_meminfo.upper_memory = mb_info->mem_upper * 1024;

  // TODO(aoates): this isn't totally correct.
  if (g_meminfo.upper_memory > MAX_MEMORY_BYTES) {
    g_meminfo.upper_memory =
        MAX_MEMORY_BYTES - g_meminfo.lower_memory - PAGE_SIZE;
  }

  g_meminfo.phys_map_start = KERNEL_PHYS_MAP_START;
  g_meminfo.phys_map_length = 0;  // We'll set this when we do the mapping.
  g_meminfo.heap_start = START_HEAP;
  g_meminfo.heap_end = END_HEAP;
  g_meminfo.kernel_stack_base = stack + KERNEL_VIRT_START;
  return &g_meminfo;
}

memory_info_t* mem_init(uint32_t magic, multiboot_info_t* multiboot_info_phys,
                        uint32_t stack) {
  kassert_phys(magic == 0x2BADB002);

  memory_info_t* meminfo = create_initial_meminfo(multiboot_info_phys, stack);
  meminfo = setup_paging(meminfo);
  // We are now in virtual memory!
  return meminfo;
}
