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

#include "common/debug.h"
#include "common/kassert.h"
#include "memory.h"
#include "page_alloc.h"

#define SUPPORTS_INVPLG_INSTRUCTION 0

// The current stack of free page frame addresses.  The stack is guarded on both
// ends by an invalid (non-aligned) page frames.
static uint32_t* free_frame_stack = 0;
static uint32_t stack_size = -1;
static uint32_t stack_idx = -1;  // points to the next free element on the stack.

// Initialize the allocator with the given meminfo.
void page_frame_alloc_init(memory_info_t* meminfo) {
  const uint32_t total_frames =
      (meminfo->lower_memory + meminfo->upper_memory) / PAGE_SIZE;
  // Get the first free frame address after the kernel.
  const uint32_t kernel_end_page = next_page(meminfo->kernel_end_phys);

  // Take all the frames above what the kernel is already using.  Don't include
  // frames before the kernel (<1MB).
  const uint32_t free_frames = total_frames - (kernel_end_page / PAGE_SIZE);

  // Allocate a stack of the appropriate size.  We need 4 bytes per free frame,
  // plus 8 bytes for guard addresses.  Round up to use an even number of pages
  // for the stack.
  stack_size = free_frames * 4 + 8;
  stack_size = next_page(stack_size); // round up.

  // The stack will live directly above the kernel (at the next page boundary).
  free_frame_stack = (uint32_t*)next_page(meminfo->kernel_end_virt);

  // Fill the stack with crap.
  for (uint32_t i = 0; i < stack_size; ++i) {
    free_frame_stack[i] = 0xDEADBEEF;
  }

  // Push each free frame onto the stack.  Don't count the frames we just used
  // for the stack, though.
  stack_idx = 0;
  uint32_t address = kernel_end_page + stack_size;
  for (uint32_t i = 0; i < free_frames - (stack_size / PAGE_SIZE); ++i) {
    KASSERT(is_page_aligned(address));
    KASSERT(address + PAGE_SIZE <= total_frames * PAGE_SIZE);

    free_frame_stack[stack_idx++] = address;
    address += PAGE_SIZE;
  }
}

uint32_t page_frame_alloc() {
  if (stack_idx <= 0) {
    return 0;
  }

  uint32_t frame = free_frame_stack[--stack_idx];

  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Fill the page with crap.
    uint32_t virt_frame = phys2virt(frame);
    for (int i = 0; i < PAGE_SIZE / 4; ++i) {
      ((uint32_t*)virt_frame)[i] = 0xCAFEBABE;
    }
  }

  return frame;
}

void page_frame_free(uint32_t frame_addr) {
  KASSERT(is_page_aligned(frame_addr));
  KASSERT(stack_idx <= stack_size);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Check that the page frame isn't already free.
    for (uint32_t i = 0; i < stack_idx; ++i) {
      KASSERT(free_frame_stack[i] != frame_addr);
    }

    // Fill the page with crap.
    uint32_t virt_frame = phys2virt(frame_addr);
    for (int i = 0; i < PAGE_SIZE / 4; ++i) {
      ((uint32_t*)virt_frame)[i] = 0xDEADBEEF;
    }
  }

  page_frame_free_nocheck(frame_addr);
}

void page_frame_free_nocheck(uint32_t frame) {
  const uint32_t frame_addr = (uint32_t)frame;
  KASSERT(is_page_aligned(frame_addr));
  KASSERT(stack_idx <= stack_size);

  free_frame_stack[stack_idx++] = frame_addr;
}

// Returns the current page directory.
static inline uint32_t* get_page_directory() {
  return (uint32_t*)0xFFFFF000;
}

// Returns the page table entry for the given page address.  Requires that the
// appropriate page table already exists and is pointed to by the page
// directory.
static inline uint32_t* get_page_table_entry(uint32_t virt) {
  return (uint32_t*)0xFFC00000 + (virt / PAGE_SIZE);
}

// Invalidate the TLB entry for the given virtual address.
static inline void invalidate_tlb(uint32_t virt) {
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
//
// TODO(aoates): if we create a new page table after fork() has happened, how
// does that entry in the page directory get propogated to other processes?
// If it's a kernel mapping, we want to share it between all processes, but
// we'll currently just set it in the current one only.
//
// Maybe the solution is, at boot create (in the initial page directory) blank
// page tables for all kernel mapped memory (e.g. the kernel heap), which we can
// then point to from all subsequent page directories and update with global
// reach.
static uint32_t* get_or_create_page_table_entry(uint32_t virt, int create) {
  uint32_t* page_directory = get_page_directory();
  const uint32_t page_idx = virt / PAGE_SIZE;
  const uint32_t page_table_idx = page_idx / PTE_NUM_ENTRIES;

  if (page_directory[page_table_idx] & PDE_PRESENT) {
    return get_page_table_entry(virt);
  } else if (!create) {
    return 0x0;
  } else {
    // Allocate a new page table.
    uint32_t pte_phys_addr = page_frame_alloc();
    KASSERT(pte_phys_addr);
    page_directory[page_table_idx] = pte_phys_addr | PDE_WRITABLE | PDE_PRESENT;

    // Initialize the new page table.  Get the *first* address of the new page
    // table.
    uint32_t* pte_virt_addr = get_page_table_entry(
        page_table_idx * PTE_NUM_ENTRIES * PAGE_SIZE);
    for (uint32_t i = 0; i < PTE_NUM_ENTRIES; ++i) {
      pte_virt_addr[i] = 0 | PDE_WRITABLE;
    }

    return get_page_table_entry(virt);
  }
}

// TODO(aoates): make kernel mappings PDE_GLOBAL for efficiency.
void page_frame_map_virtual(uint32_t virt, uint32_t phys) {
  KASSERT(virt % PAGE_SIZE == 0);
  KASSERT(phys % PAGE_SIZE == 0);

  uint32_t* pte = get_or_create_page_table_entry(virt, 1);
  *pte = phys | PTE_WRITABLE | PTE_PRESENT;
  invalidate_tlb(virt);
}

void page_frame_unmap_virtual(uint32_t virt) {
  KASSERT(virt % PAGE_SIZE == 0);
  uint32_t* pte = get_or_create_page_table_entry(virt, 0);
  if (pte) {
    // Mark the page as non-present.
    *pte &= ~PTE_PRESENT;
    invalidate_tlb(virt);
  }
}
