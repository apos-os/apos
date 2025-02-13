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

#include "archs/i586/internal/load/mem_init.h"
#include "archs/i586/internal/memory/page_tables.h"
#include "common/linker_symbols.h"
#include "memory/memory.h"

// We will additionally set up a linear map for physical memory into the
// kernel's virtual memory space, starting at the following address.
const addr_t KERNEL_PHYS_MAP_START = 0xE0000000;

// The maximum number of bytes we'll physically map into the region starting at
// KERNEL_PHYS_MAP_START.
const addr_t KERNEL_PHYS_MAP_MAX_LENGTH = 0x10000000;

// Upper segment for top 64MB section of physical memory for PCI MMIO.
// TODO(aoates): this shouldn't be hard coded, but I'm not sure where to extract
// it from.  ACPI tables?
const addr_t KERNEL_PHYS_MAP_UPPER = 0xF0000000;
const addr_t KERNEL_PHYS_MAP_UPPER_LEN = 0x4000000;

// The maximum amount of physical memory we support (due to the
// KERNEL_PHYS_MAP_START).
// TODO(aoates): add option to page allocator to allocate only from
// physically-mapped region, then remove this artificial cap.
const addrdiff_t MAX_MEMORY_BYTES = 0x10000000;

// The virtual start and end addresses of the kernel heap.
const addr_t START_HEAP = 0xD0000000;
const addr_t HEAP_LEN =   0x10000000;

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
static void kassert_page_aligned(addr_t x) {
  kassert_phys((x & PAGE_OFFSET_MASK) == 0);
}

// Allocate an (aligned) page at the end of the current kernel physical space,
// updating meminfo->kernel_end_phys as necessary.
static uint32_t* kalloc_page(memory_info_t* meminfo) {
  uint32_t* addr = (uint32_t*)0xDEADBEEF;
  addr_t kernel_phys_end = meminfo->kernel.phys.base + meminfo->kernel.phys.len;
  if ((kernel_phys_end & PAGE_OFFSET_MASK) == 0) {
    addr = (uint32_t*)kernel_phys_end;
  } else {
    addr = (uint32_t*)((kernel_phys_end & PAGE_INDEX_MASK) + PAGE_SIZE);
  }
  meminfo->kernel.phys.len =
      (addr_t)addr - meminfo->kernel.phys.base + PAGE_SIZE;
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

  // Create two initial PTEs as well.  Identity map the first n * 4MB, and map
  // the higher-half kernel to the first physical n * 4MB as well.
  // Note: Keep this in sync with load/kernel_init.c (which undoes the first
  // mapping).
  kassert_phys((uint32_t)&KERNEL_END_SYMBOL - KERNEL_VIRT_START <
               KERNEL_MAP_4MB_REGIONS * (PAGE_SIZE * PAGE_SIZE / 4));
  for (i = 0; i < KERNEL_MAP_4MB_REGIONS; ++i) {
    const uint32_t offset = i * PTE_NUM_ENTRIES * PAGE_SIZE;
    uint32_t* page_table1 = kalloc_page(meminfo);
    map_linear_page_table(page_directory, page_table1, offset, offset);
    uint32_t* page_table2 = kalloc_page(meminfo);
    map_linear_page_table(page_directory, page_table2,
                          KERNEL_VIRT_START + offset, offset);
  }

  // Identity map the first KERNEL_PHYS_MAP_MAX_LENGTH bytes of physical memory
  // as well.
  uint32_t phys_map_len = meminfo->mainmem_phys.len;
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
  meminfo->phys_maps[0].phys.len = phys_map_len;

  // Map the highest portion of memory.
  kassert_phys(KERNEL_PHYS_MAP_UPPER_LEN % MIN_GLOBAL_MAPPING_SIZE == 0);
  addr_t virt_addr = KERNEL_PHYS_MAP_UPPER;
  addr_t phys_addr = 0xFFFFFFFF - KERNEL_PHYS_MAP_UPPER_LEN + 1;
  meminfo->phys_maps[1].virt_base = virt_addr;
  meminfo->phys_maps[1].phys.base = phys_addr;
  meminfo->phys_maps[1].phys.len = KERNEL_PHYS_MAP_UPPER_LEN;
  while (virt_addr - KERNEL_PHYS_MAP_UPPER < KERNEL_PHYS_MAP_UPPER_LEN) {
    uint32_t* ident_page_table = kalloc_page(meminfo);
    map_linear_page_table(page_directory, ident_page_table, virt_addr,
                          phys_addr);
    phys_addr += PTE_NUM_ENTRIES * PAGE_SIZE;
    virt_addr += PTE_NUM_ENTRIES * PAGE_SIZE;
  }

  // Finally, map the last PDE entry onto itself so we can always access the
  // current PDE/PTEs without having to map them in explicitly.
  kassert_page_aligned((uint32_t)page_directory);
  page_directory[PDE_NUM_ENTRIES - 1] =
      (uint32_t)page_directory | PDE_WRITABLE | PDE_PRESENT;

  // Update meminfo.
  meminfo->kernel.virt_base = meminfo->kernel.phys.base + KERNEL_VIRT_START;
  meminfo->kernel_mapped.base = KERNEL_VIRT_START;
  // We mapped a N PTEs (4MB each) for use by the kernel.
  meminfo->kernel_mapped.len =
      KERNEL_MAP_4MB_REGIONS * PTE_NUM_ENTRIES * PAGE_SIZE;
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

  g_meminfo.kernel.phys.base =
      (addr_t)(&KERNEL_START_SYMBOL) - KERNEL_VIRT_START;
  // Account for the memory_info_t we just allocated.
  g_meminfo.kernel.phys.len =
      (addr_t)(&KERNEL_END_SYMBOL) - (addr_t)(&KERNEL_START_SYMBOL);

  g_meminfo.kernel.virt_base = 0;
  g_meminfo.kernel_mapped.base = g_meminfo.kernel_mapped.len = 0;

  kassert_phys((mb_info->flags & MULTIBOOT_INFO_MEMORY) != 0);
  g_meminfo.mainmem_phys.base = 0;
  g_meminfo.mainmem_phys.len = mb_info->mem_lower * 1024;
  g_meminfo.mainmem_phys.len += mb_info->mem_upper * 1024;

  if (g_meminfo.mainmem_phys.len > MAX_MEMORY_BYTES) {
    g_meminfo.mainmem_phys.len = MAX_MEMORY_BYTES;
  }

  g_meminfo.phys_maps[0].phys.base = 0;
  g_meminfo.phys_maps[0].virt_base = KERNEL_PHYS_MAP_START;
  g_meminfo.phys_maps[0].phys.len = 0;  // We'll set this when we do the mapping
  for (int i = 1; i < MEM_MAX_PHYS_MAPS; ++i) {
    g_meminfo.phys_maps[i].phys.base = g_meminfo.phys_maps[i].phys.len =
        g_meminfo.phys_maps[i].virt_base = 0;
  }
  g_meminfo.heap.base = START_HEAP;
  g_meminfo.heap.len = HEAP_LEN;
  g_meminfo.heap_size_max = g_meminfo.heap.len;
  g_meminfo.thread0_stack.base = stack + KERNEL_VIRT_START;
  g_meminfo.thread0_stack.len = 0x4000;
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
