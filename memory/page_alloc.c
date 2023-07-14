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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "arch/memory/layout.h"
#include "common/debug.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/page_alloc.h"

// The number of frames we reserve for DMA by device drivers.  This is a crappy
// way to do this---it's static, so it limits the number of devices that can be
// used, but also wastes memory if we don't use it all.
#define DMA_RESERVED_FRAMES 32

// The current stack of free page frame addresses.  The stack is guarded on both
// ends by an invalid (non-aligned) page frames.
static phys_addr_t* free_frame_stack = 0;
static size_t stack_size = -1;
static size_t stack_idx = -1;  // points to the next free element on the stack.

// Address of the first DMA-reserved page frame (corresponds to index 0 in the
// above array).
static phys_addr_t dma_reserved_first_frame;

// Index of the first free DMA-reserved frame.  We don't (currently) support
// de-allocating the DMA ranges, so we just keep a high-water mark as we go.
static size_t dma_reserved_first_free_idx = 0;

// Initialize the allocator with the given meminfo.
void page_frame_alloc_init(memory_info_t* meminfo) {
  const size_t total_frames =
      (meminfo->lower_memory + meminfo->upper_memory) / PAGE_SIZE;
  // Get the first free frame address after the kernel.
  const phys_addr_t kernel_end_page = next_page(meminfo->kernel_end_phys);
  KASSERT(meminfo->phys_mainmem_begin == 0);
  phys_addr_t next_free_frame = kernel_end_page;

  // Reserve same frames for DMA usage.  The DMA pages will live directly above
  // the kernel (at the next page boundary).
  dma_reserved_first_frame = next_free_frame;
  next_free_frame += DMA_RESERVED_FRAMES * PAGE_SIZE;

  // Take all the frames above what the kernel is already using.  Don't include
  // frames before the kernel (<1MB).
  const size_t free_frames =
      total_frames - (kernel_end_page / PAGE_SIZE) - DMA_RESERVED_FRAMES;

  // Allocate a stack of the appropriate size.  We need sizeof(phys_addr_t)
  // bytes per free frame, plus twice that for guard addresses.  Round up to use
  // an even number of pages for the stack.
  stack_size = (free_frames + 2) * sizeof(phys_addr_t);
  stack_size = next_page(stack_size); // round up.

  const addr_t stack_end = next_page(phys2virt(next_free_frame)) + stack_size;
  KASSERT_MSG(meminfo->phys_map_start + meminfo->phys_map_length >= stack_end,
              "Not enough memory in physical-mapped region for free page stack "
              "(mapped region goes to %#" PRIxADDR
              ", stack would go to %#" PRIxADDR,
              meminfo->phys_map_start + meminfo->phys_map_length, stack_end);

  // The stack will live directly above the DMA-reserved block.
  free_frame_stack = (phys_addr_t*)phys2virt(next_free_frame);
  next_free_frame += stack_size;

  // Fill the stack with crap.
  kmemset(free_frame_stack, 0xBC, stack_size);

  // Push each free frame onto the stack.  Don't count the frames we just used
  // for the stack, though.
  stack_idx = 0;
  phys_addr_t address = next_free_frame;
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
    KASSERT_DBG(frame < get_global_meminfo()->lower_memory +
                            get_global_meminfo()->upper_memory);
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
    KASSERT_DBG(frame_addr < get_global_meminfo()->lower_memory +
                                 get_global_meminfo()->upper_memory);
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

phys_addr_t page_frame_dma_alloc(size_t pages) {
  if (pages == 0 || pages > DMA_RESERVED_FRAMES - dma_reserved_first_free_idx) {
    return 0;
  }
  const phys_addr_t result =
      dma_reserved_first_frame + dma_reserved_first_free_idx * PAGE_SIZE;
  dma_reserved_first_free_idx += pages;
  return result;
}
