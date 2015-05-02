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

#include <stddef.h>
#include <stdint.h>

#include "arch/memory/layout.h"
#include "arch/memory/page_alloc.h"
#include "archs/i586/internal/memory/page_tables.h"
#include "common/debug.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/flags.h"
#include "memory/memory.h"

#define SUPPORTS_INVPLG_INSTRUCTION 0

typedef addr_t pte_t;
typedef addr_t pde_t;

// The current stack of free page frame addresses.  The stack is guarded on both
// ends by an invalid (non-aligned) page frames.
static phys_addr_t* free_frame_stack = 0;
static size_t stack_size = -1;
static size_t stack_idx = -1;  // points to the next free element on the stack.

// Initialize the allocator with the given meminfo.
void page_frame_alloc_init(memory_info_t* meminfo) {
  const size_t total_frames =
      (meminfo->lower_memory + meminfo->upper_memory) / PAGE_SIZE;
  // Get the first free frame address after the kernel.
  const phys_addr_t kernel_end_page = next_page(meminfo->kernel_end_phys);

  // Take all the frames above what the kernel is already using.  Don't include
  // frames before the kernel (<1MB).
  const size_t free_frames = total_frames - (kernel_end_page / PAGE_SIZE);

  // Allocate a stack of the appropriate size.  We need 4 bytes per free frame,
  // plus 8 bytes for guard addresses.  Round up to use an even number of pages
  // for the stack.
  stack_size = free_frames * 4 + 8;
  stack_size = next_page(stack_size); // round up.

  const addr_t stack_end = next_page(meminfo->kernel_end_virt) + stack_size;
  KASSERT_MSG(meminfo->mapped_end >= stack_end,
              "Not enough memory in kernel-mapped region for free page stack "
              "(mapped region goes to %#" PRIxADDR
              ", stack would go to %#" PRIxADDR,
              meminfo->mapped_end, stack_end);

  // The stack will live directly above the kernel (at the next page boundary).
  free_frame_stack = (phys_addr_t*)next_page(meminfo->kernel_end_virt);

  // Fill the stack with crap.
  kmemset(free_frame_stack, 0xBC, stack_size);

  // Push each free frame onto the stack.  Don't count the frames we just used
  // for the stack, though.
  stack_idx = 0;
  phys_addr_t address = kernel_end_page + stack_size;
  for (size_t i = 0; i < free_frames - (stack_size / PAGE_SIZE); ++i) {
    KASSERT(is_page_aligned(address));
    KASSERT(address + PAGE_SIZE <= total_frames * PAGE_SIZE);

    free_frame_stack[stack_idx++] = address;
    address += PAGE_SIZE;
  }
}

phys_addr_t page_frame_alloc() {
  if (stack_idx <= 0) {
    return 0;
  }

  phys_addr_t frame = free_frame_stack[--stack_idx];

  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Fill the page with crap.
    addr_t virt_frame = phys2virt(frame);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint32_t); ++i) {
      ((uint32_t*)virt_frame)[i] = 0xCAFEBABE;
    }
  }

  return frame;
}

void page_frame_free(phys_addr_t frame_addr) {
  KASSERT(is_page_aligned(frame_addr));
  KASSERT(stack_idx <= stack_size);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Check that the page frame isn't already free.
    for (size_t i = 0; i < stack_idx; ++i) {
      KASSERT(free_frame_stack[i] != frame_addr);
    }

    // Fill the page with crap.
    addr_t virt_frame = phys2virt(frame_addr);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint32_t); ++i) {
      ((uint32_t*)virt_frame)[i] = 0xDEADBEEF;
    }
  }

  page_frame_free_nocheck(frame_addr);
}

void page_frame_free_nocheck(phys_addr_t frame_addr) {
  KASSERT(is_page_aligned(frame_addr));
  KASSERT(stack_idx <= stack_size);

  free_frame_stack[stack_idx++] = frame_addr;
}

// Returns the current page directory.
static inline pde_t* get_page_directory(void) {
  return (pde_t*)0xFFFFF000;
}

// Returns the page table entry for the given page address.  Requires that the
// appropriate page table already exists and is pointed to by the page
// directory.
static inline pte_t* get_page_table_entry(addr_t virt) {
  return (pte_t*)0xFFC00000 + (virt / PAGE_SIZE);
}

// Invalidate the TLB entry for the given virtual address.
static inline void invalidate_tlb(addr_t virt) {
  _Static_assert(sizeof(virt) == sizeof(uint32_t), "Not 32-bit");
  if (SUPPORTS_INVPLG_INSTRUCTION) {
    asm volatile (
        "invlpg %0\n\t"
        :: "m"(virt));
  } else {
    asm volatile (
        "mov %%cr3, %%eax\n\t"
        "mov %%eax, %%cr3\n\t"
        ::: "eax");
  }
}

// Given a virtual page address, returns a pointer to the page table entry
// responsible for page.  If create is non-zero, and the page table doesn't
// exist, a page table is allocated and initialized for it.
static pte_t* get_or_create_page_table_entry(addr_t virt, bool create) {
  pde_t* page_directory = get_page_directory();
  const size_t page_idx = virt / PAGE_SIZE;
  const size_t page_table_idx = page_idx / PTE_NUM_ENTRIES;

  if (page_directory[page_table_idx] & PDE_PRESENT) {
    return get_page_table_entry(virt);
  } else if (!create) {
    return 0x0;
  } else {
    // Allocate a new page table.
    // TODO(aoates): should we bother marking PDEs as non-writable or
    // non-user-accessible?
    phys_addr_t pte_phys_addr = page_frame_alloc();
    KASSERT(pte_phys_addr);
    KASSERT_DBG((pte_phys_addr & PDE_ADDRESS_MASK) == pte_phys_addr);
    page_directory[page_table_idx] =
        pte_phys_addr | PDE_USER_ACCESS | PDE_WRITABLE | PDE_PRESENT;

    // Initialize the new page table.  Get the *first* address of the new page
    // table.
    pte_t* pte_virt_addr = get_page_table_entry(
        page_table_idx * PTE_NUM_ENTRIES * PAGE_SIZE);
    for (size_t i = 0; i < PTE_NUM_ENTRIES; ++i) {
      pte_virt_addr[i] = 0;
    }

    return get_page_table_entry(virt);
  }
}

// TODO(aoates): make kernel mappings PDE_GLOBAL for efficiency.
void page_frame_map_virtual(addr_t virt, phys_addr_t phys, int prot,
                            mem_access_t access, int flags) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(phys % PAGE_SIZE == 0);
  KASSERT(access == MEM_ACCESS_KERNEL_ONLY ||
          access == MEM_ACCESS_KERNEL_AND_USER);
  KASSERT(flags == 0 || flags == MEM_GLOBAL);

  // The PDE entry we may create will automatically get the most permissive
  // flags.
  pte_t* pte = get_or_create_page_table_entry(virt, true);
  *pte = phys | PTE_PRESENT;
  if (prot & MEM_PROT_WRITE) *pte |= PTE_WRITABLE;
  if (access == MEM_ACCESS_KERNEL_AND_USER) *pte |= PTE_USER_ACCESS;
  if (flags & MEM_GLOBAL) *pte |= PTE_GLOBAL;
  invalidate_tlb(virt);
}

void page_frame_unmap_virtual(addr_t virt) {
  page_frame_unmap_virtual_range(virt, PAGE_SIZE);
}

void page_frame_unmap_virtual_range(addr_t virt, addrdiff_t length) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(length % PAGE_SIZE == 0);
  for (size_t i = 0; i < length / PAGE_SIZE; ++i) {
    pte_t* pte = get_or_create_page_table_entry(virt + i * PAGE_SIZE, false);
    if (pte) {
      // Mark the page as non-present.
      *pte &= ~PTE_PRESENT;
      invalidate_tlb(virt);
    }
  }
}

page_dir_ptr_t page_frame_alloc_directory() {
  phys_addr_t dir_phys = page_frame_alloc();
  KASSERT(dir_phys);
  KASSERT_DBG((dir_phys & PDE_ADDRESS_MASK) == dir_phys);

  pde_t* dir = (pde_t*)phys2virt(dir_phys);
  for (size_t i = 0; i < PDE_NUM_ENTRIES; ++i) {
    dir[i] = 0;
  }

  // Self-map the page directory in the last 4MB of the address space.
  dir[PDE_NUM_ENTRIES - 1] = dir_phys | PDE_WRITABLE | PDE_PRESENT;

  return dir_phys;
}

void page_frame_free_directory(page_dir_ptr_t page_directory) {
  KASSERT(page_directory);
  KASSERT(page_directory % PAGE_SIZE == 0);
  page_frame_free(page_directory);
}

void page_frame_init_global_mapping(addr_t addr, addr_t length) {
  KASSERT(addr % MIN_GLOBAL_MAPPING_SIZE == 0);
  KASSERT(length % MIN_GLOBAL_MAPPING_SIZE == 0);

  // For each PDE in the current page directory, make sure a page table is
  // allocated.  This page table will be shared between all processes (by making
  // their page directories point to the same ones.
  // TODO(aoates): this will have overflow issues if mapping at the end of the
  // address space.
  for (addr_t pt_addr = addr; pt_addr < addr + length;
       pt_addr += MIN_GLOBAL_MAPPING_SIZE) {
    // pt_addr is the first address of the region represented by each page
    // table.
    // TODO(aoates): set the GLOBAL flag on each of these mappings.
    get_or_create_page_table_entry(pt_addr, true);
  }
}

void page_frame_link_global_mapping(page_dir_ptr_t target,
                                    addr_t addr, addr_t length) {
  // Copy all the page directory entries created in
  // page_frame_init_global_mapping() from the current address space into the
  // new page directory.
  KASSERT(addr % MIN_GLOBAL_MAPPING_SIZE == 0);
  KASSERT(length % MIN_GLOBAL_MAPPING_SIZE == 0);

  pde_t* source = get_page_directory();
  pde_t* target_virt = (pde_t*)phys2virt(target);

  // TODO(aoates): this will have overflow issues if mapping at the end of the
  // address space.
  for (size_t pde_idx = addr / MIN_GLOBAL_MAPPING_SIZE;
       pde_idx < (addr + length) / MIN_GLOBAL_MAPPING_SIZE;
       pde_idx++) {
    // TODO(aoates): do we want to to check or reset any of the flags in the
    // PDE?
    KASSERT(source[pde_idx] != 0);
    target_virt[pde_idx] = source[pde_idx];
  }
}
