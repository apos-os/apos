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
#include "memory.h"

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

  // Fill the page with crap.
  uint32_t virt_frame = phys2virt(frame);
  for (int i = 0; i < PAGE_SIZE / 4; ++i) {
    ((uint32_t*)virt_frame)[i] = 0xCAFEBABE;
  }

  return frame;
}

void page_frame_free(uint32_t frame) {
  const uint32_t frame_addr = (uint32_t)frame;
  KASSERT(is_page_aligned(frame_addr));

  // Check that the page frame isn't already free.
  for (uint32_t i = 0; i < stack_idx; ++i) {
    KASSERT(free_frame_stack[i] != frame_addr);
  }

  KASSERT(stack_idx <= stack_size);

  // Fill the page with crap.
  uint32_t virt_frame = phys2virt(frame);
  for (int i = 0; i < PAGE_SIZE / 4; ++i) {
    ((uint32_t*)virt_frame)[i] = 0xDEADBEEF;
  }
  free_frame_stack[stack_idx++] = frame_addr;
}
