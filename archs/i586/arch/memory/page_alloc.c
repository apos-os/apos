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
#include "common/debug.h"
#include "common/kassert.h"
#include "common/kstring.h"

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
