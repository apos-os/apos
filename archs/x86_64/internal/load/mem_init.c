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

#include "archs/x86_64/internal/load/mem_init.h"
#include "archs/x86_64/internal/memory/page_tables.h"
#include "memory/memory.h"

// Memory limits of the kernel --- symbols defined at the start and end of the
// kernel.  Defined in loader.s.
//
// Note: these are the VIRTUAL addresses of the start and end.
extern uint64_t KERNEL_START_SYMBOL;
extern uint64_t KERNEL_END_SYMBOL;

// We will additionally set up a linear map for physical memory into the
// kernel's virtual memory space, starting at the following address.
const addr_t KERNEL_PHYS_MAP_START = 0xFFFFFFFFE0000000;

// The maximum number of bytes we'll physically map into the region starting at
// KERNEL_PHYS_MAP_START.
const addr_t KERNEL_PHYS_MAP_MAX_LENGTH = 0x10000000;

// The maximum amount of physical memory we support (due to the
// KERNEL_PHYS_MAP_START).
// TODO(aoates): add option to page allocator to allocate only from
// physically-mapped region, then remove this artificial cap.
const addrdiff_t MAX_MEMORY_BYTES = 0x10000000;

// The virtual start and end addresses of the kernel heap.
const addr_t START_HEAP = 0xFFFFFFFFD0000000;
const addr_t END_HEAP =   0xFFFFFFFFE0000000;

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
static uint64_t* kalloc_page(memory_info_t* meminfo) {
  uint64_t* addr = (uint64_t*)0xDEADBEEFDEADBEEF;
  if ((meminfo->kernel_end_phys & PAGE_OFFSET_MASK) == 0) {
    addr = (uint64_t*)meminfo->kernel_end_phys;
  } else {
    addr = (uint64_t*)(
        (meminfo->kernel_end_phys & PAGE_INDEX_MASK) + PAGE_SIZE);
  }
  meminfo->kernel_end_phys = (uint64_t)addr + PAGE_SIZE;
  return addr;
}

// Create a page table with a linear mapping from virt_base to phys_base.  Then
// install the page table in the given PD, PDPT, and PML4, allocating them if
// necessary.  virt_base must be PDE-size aligned (that is, must be 2MB aligned
// if each PDE represents 2MB).
static void map_linear_page_table(memory_info_t* meminfo, uint64_t* pml4,
                                  uint64_t virt_base, uint64_t phys_base) {
  // Ensure everything is page-aligned.
  kassert_page_aligned((uint64_t)pml4);
  kassert_page_aligned(virt_base);
  kassert_page_aligned(phys_base);
  kassert_phys((virt_base % (PAGE_SIZE * PD_NUM_ENTRIES)) == 0);

  // Mask out the leading bits of the canonicalized address, then calculate
  // indices (from the start of memory).
  uint64_t page_idx = ((virt_base & VIRT_ADDR_MASK) / PAGE_SIZE);
  uint64_t pt_idx = page_idx / PT_NUM_ENTRIES;
  uint64_t pd_idx = pt_idx / PD_NUM_ENTRIES;
  uint64_t pdpt_idx = pd_idx / PDPT_NUM_ENTRIES;
  kassert_phys(page_idx % PT_NUM_ENTRIES == 0);
  kassert_phys(pdpt_idx < PML4_NUM_ENTRIES);

  if ((pml4[pdpt_idx] & PML4E_PRESENT) == 0) {
    uint64_t* pdpt = (uint64_t*)kalloc_page(meminfo);
    for (int i = 0; i < PDPT_NUM_ENTRIES; ++i) {
      pdpt[i] = 0;
    }
    pml4[pdpt_idx] = (uint64_t)pdpt | PML4E_WRITABLE | PML4E_PRESENT;
  }

  uint64_t* pdpt = (uint64_t*)(pml4[pdpt_idx] & PML4E_ADDRESS_MASK);
  if ((pdpt[pd_idx % PDPT_NUM_ENTRIES] & PDPTE_PRESENT) == 0) {
    uint64_t* pd = (uint64_t*)kalloc_page(meminfo);
    for (int i = 0; i < PD_NUM_ENTRIES; ++i) {
      pd[i] = 0;
    }
    pdpt[pd_idx % PDPT_NUM_ENTRIES] =
        (uint64_t)pd | PDPTE_WRITABLE | PDPTE_PRESENT;
  }

  uint64_t* pd =
      (uint64_t*)(pdpt[pd_idx % PDPT_NUM_ENTRIES] & PDPTE_ADDRESS_MASK);
  // TODO(aoates): set global flag.
  pd[pt_idx % PD_NUM_ENTRIES] =
      phys_base | PDE_LARGE_PAGES | PDE_WRITABLE | PDE_PRESENT;
}

// Set up page tables and enable paging.  Updates meminfo as it allocates and
// creates a virtual memory space.  Returns the new (virtual) address of
// meminfo.
static memory_info_t* setup_paging(memory_info_t* meminfo) {
  // TODO(aoates): reuse pages statically allocated for the initial page tables.
  uint64_t* pml4 = kalloc_page(meminfo);

  for (int i = 0; i < PML4_NUM_ENTRIES; ++i) {
    pml4[i] = 0;
  }

  // We already have an identity map for the kernel code (set up before we
  // entered 64-bit mode), so just create the virtual mapping for the kernel
  // code.
  kassert_phys((uint64_t)&KERNEL_END_SYMBOL - KERNEL_VIRT_START <
               KERNEL_MAP_2MB_REGIONS * (PAGE_SIZE * PT_NUM_ENTRIES));
  for (int i = 0; i < KERNEL_MAP_2MB_REGIONS; ++i) {
    const uint64_t phys_addr = i * (PAGE_SIZE * PT_NUM_ENTRIES);
    kassert_phys(((phys_addr) & ~PDE_ADDRESS_MASK) == 0);
    map_linear_page_table(meminfo, pml4, phys_addr, phys_addr);
    map_linear_page_table(meminfo, pml4,
                          KERNEL_VIRT_START + phys_addr, phys_addr);
  }

  // Identity map the first KERNEL_PHYS_MAP_MAX_LENGTH bytes of physical memory
  // as well.
  uint64_t phys_map_len = meminfo->lower_memory + meminfo->upper_memory;
  if (phys_map_len > KERNEL_PHYS_MAP_MAX_LENGTH) {
    phys_map_len = KERNEL_PHYS_MAP_MAX_LENGTH;
  }
  uint64_t ident_addr = 0;
  while (ident_addr < phys_map_len) {
    map_linear_page_table(meminfo, pml4,
                          ident_addr + KERNEL_PHYS_MAP_START, ident_addr);
    ident_addr += PT_NUM_ENTRIES * PAGE_SIZE;
  }
  meminfo->phys_map_length = phys_map_len;

  // Update meminfo.
  meminfo->kernel_start_virt = meminfo->kernel_start_phys + KERNEL_VIRT_START;
  meminfo->kernel_end_virt = meminfo->kernel_end_phys + KERNEL_VIRT_START;
  meminfo->mapped_start = KERNEL_VIRT_START;
  // We mapped a N PTEs (4MB each) for use by the kernel.
  meminfo->mapped_end =
      KERNEL_VIRT_START + KERNEL_MAP_2MB_REGIONS * PT_NUM_ENTRIES * PAGE_SIZE;
  // TODO(aoates): fix/rename this?
  meminfo->kernel_page_directory = (page_dir_ptr_t)pml4;

  // Install the new PML4.
  asm volatile
      ("mov %0, %%cr3"
       :: "b"(pml4));

  // Return the virtual-mapped address of meminfo.
  return (memory_info_t*)(((uint64_t)meminfo) + KERNEL_VIRT_START);
}

// Allocates a memory_info_t at the end of the kernel and fills it in with what
// we know.
static memory_info_t* create_initial_meminfo(multiboot_info_t* mb_info,
                                             uint64_t stack) {
  // Statically allocate a memory_info_t.  We will pass this around to keep
  // track of how much memory we allocate here, updating
  // meminfo->kernel_end_{phys, virt} as needed.
  static memory_info_t g_meminfo;

  g_meminfo.kernel_start_phys =
      (uint64_t)(&KERNEL_START_SYMBOL) - KERNEL_VIRT_START;
  // Account for the memory_info_t we just allocated.
  g_meminfo.kernel_end_phys =
      (uint64_t)(&KERNEL_END_SYMBOL) - KERNEL_VIRT_START;

  g_meminfo.kernel_start_virt = g_meminfo.kernel_end_virt = 0;
  g_meminfo.mapped_start = g_meminfo.mapped_end = 0;

  kassert_phys((mb_info->flags & MULTIBOOT_INFO_MEMORY) != 0);
  g_meminfo.phys_mainmem_begin = 0;
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
  g_meminfo.kernel_stack_len = 0x8000;
  return &g_meminfo;
}

memory_info_t* mem_init(uint64_t magic, multiboot_info_t* multiboot_info_phys,
                        uint64_t stack) {
  kassert_phys(magic == 0x2BADB002);

  memory_info_t* meminfo = create_initial_meminfo(multiboot_info_phys, stack);
  meminfo = setup_paging(meminfo);
  // We are now in virtual memory!
  return meminfo;
}
