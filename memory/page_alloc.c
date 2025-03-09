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
#include "arch/proc/stack_trace.h"
#include "common/attributes.h"
#include "common/debug.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "common/stack_trace_table.h"
#include "dev/interrupts.h"
#include "memory/page_alloc.h"

// The number of frames we reserve for DMA by device drivers.  This is a crappy
// way to do this---it's static, so it limits the number of devices that can be
// used, but also wastes memory if we don't use it all.
#define DMA_RESERVED_FRAMES 32

// The current stack of free page frame addresses.  The stack is guarded on both
// ends by an invalid (non-aligned) page frames.
static phys_addr_t* free_frame_stack = 0;
static size_t stack_entries = -1;
static size_t stack_idx = -1;  // points to the next free element on the stack.

// Metadata about a raw page.
typedef struct {
#if ENABLE_KMALLOC_HEAP_PROFILE
  // If it has been allocated, the stack trace of the allocation point.
  trace_id_t trace;
#endif
  bool allocated;
} page_alloc_metadata_t;

// Metadata about all frames.  Indexed by frame number offset from the start of
// physical memory.  All (except actual metadata) const after initialization.
static page_alloc_metadata_t* g_page_md;
static size_t g_page_md_entries;
static phys_addr_t g_page_md_start;

// Address of the first DMA-reserved page frame (corresponds to index 0 in the
// above array).
static phys_addr_t dma_reserved_first_frame;

// Index of the first free DMA-reserved frame.  We don't (currently) support
// de-allocating the DMA ranges, so we just keep a high-water mark as we go.
static size_t dma_reserved_first_free_idx = 0;

static size_t meminfo_mainmem_len(const memory_info_t* meminfo) {
  return meminfo->mainmem_phys.len;
}

static size_t meminfo_mainmem_end(const memory_info_t* meminfo) {
  return meminfo->mainmem_phys.base + meminfo_mainmem_len(meminfo);
}

static page_alloc_metadata_t* get_page_md(phys_addr_t addr) {
  KASSERT_DBG(addr % PAGE_SIZE == 0);
  KASSERT_DBG(addr >= g_page_md_start);
  size_t idx = (addr - g_page_md_start) / PAGE_SIZE;
  KASSERT_DBG(idx < g_page_md_entries);
  return &g_page_md[idx];
}

// Initialize the allocator with the given meminfo.
void page_frame_alloc_init(memory_info_t* meminfo) {
  const size_t total_frames = meminfo_mainmem_len(meminfo) / PAGE_SIZE;
  // Get the first free frame address after the kernel.
  const phys_addr_t kernel_end_page =
      next_page(meminfo->kernel.phys.base + meminfo->kernel.phys.len);
  const phys_addr_t first_free_frame = kernel_end_page;
  phys_addr_t next_free_frame = first_free_frame;
  KASSERT(meminfo->mainmem_phys.base <= meminfo->kernel.phys.base);
  KASSERT(meminfo->kernel.phys.base + meminfo->kernel.phys.len <=
          meminfo_mainmem_end(meminfo));

  // Reserve same frames for DMA usage.  The DMA pages will live directly above
  // the kernel (at the next page boundary).
  dma_reserved_first_frame = next_free_frame;
  next_free_frame += DMA_RESERVED_FRAMES * PAGE_SIZE;

  // Take all the frames above what the kernel is already using.  Don't include
  // frames before the kernel (<1MB).
  const size_t initial_free_frames =
      total_frames -
      ((kernel_end_page - meminfo->mainmem_phys.base) / PAGE_SIZE) -
      DMA_RESERVED_FRAMES;
  // As we consume frames for metadata, track that here.
  size_t free_frames = initial_free_frames;

  // Metadata #1: the free frame stack.
  // Allocate a stack of the appropriate size.  We need sizeof(phys_addr_t)
  // bytes per free frame, plus twice that for guard addresses.  Round up to use
  // an even number of pages for the stack.
  size_t stack_size = (free_frames + 2) * sizeof(phys_addr_t);
  stack_size = next_page(stack_size); // round up.

  const addr_t stack_end = next_page(phys2virt(next_free_frame)) + stack_size;
  KASSERT_MSG(
      meminfo->phys_maps[0].virt_base + meminfo->phys_maps[0].phys.len >=
          stack_end,
      "Not enough memory in physical-mapped region for free page stack "
      "(mapped region goes to %#" PRIxADDR ", stack would go to %#" PRIxADDR,
      meminfo->phys_maps[0].virt_base + meminfo->phys_maps[0].phys.len,
      stack_end);

  // The stack will live directly above the DMA-reserved block.
  free_frame_stack = (phys_addr_t*)phys2virt(next_free_frame);
  next_free_frame += stack_size;
  free_frames -= (stack_size / PAGE_SIZE);

  // Fill the stack with crap.
  kmemset(free_frame_stack, 0xBC, stack_size);

  // Metadata #2: the page alloc metadata array.  For simplicity we have
  // metadata for all physical page frames (including those not allocatable).
  g_page_md_entries = ceiling_div(meminfo_mainmem_len(meminfo), PAGE_SIZE);
  g_page_md_start = meminfo->kernel.phys.base;
  size_t md_array_size = g_page_md_entries * sizeof(page_alloc_metadata_t);
  // Allocate a whole number of pages for the metadata array.
  md_array_size = align_up(md_array_size, PAGE_SIZE);
  g_page_md = (page_alloc_metadata_t*)phys2virt(next_free_frame);
  next_free_frame += md_array_size;
  free_frames -= md_array_size / PAGE_SIZE;

  // Initialize the array.
  kmemset(g_page_md, 0, md_array_size);

  // Push each free frame onto the stack.  Don't count the frames we just used
  // for the stack, though.
  stack_idx = 0;
  phys_addr_t address = next_free_frame;
  stack_entries = free_frames;
  for (size_t i = 0; i < free_frames; ++i) {
    KASSERT(is_page_aligned(address));
    KASSERT(address - meminfo->mainmem_phys.base + PAGE_SIZE <=
            total_frames * PAGE_SIZE);

    free_frame_stack[stack_idx++] = address;
    address += PAGE_SIZE;
  }
}

phys_addr_t NO_TSAN page_frame_alloc(void) {
#if ENABLE_KMALLOC_HEAP_PROFILE
  addr_t stack_trace[32];
  const int stack_trace_len = get_stack_trace(stack_trace, 32);
  KASSERT_DBG(stack_trace_len > 3);
  const trace_id_t stack_trace_id = tracetbl_put(stack_trace, stack_trace_len);
#endif

  PUSH_AND_DISABLE_INTERRUPTS();
  if (stack_idx <= 0) {
    POP_INTERRUPTS();
    return 0;
  }

  phys_addr_t frame = free_frame_stack[--stack_idx];
  page_alloc_metadata_t* md = get_page_md(frame);
  KASSERT(md->allocated == false);
  md->allocated = true;
#if ENABLE_KMALLOC_HEAP_PROFILE
  md->trace = stack_trace_id;
#endif
  POP_INTERRUPTS();

  if (ENABLE_KERNEL_SAFETY_NETS) {
    KASSERT_DBG(frame < meminfo_mainmem_end(get_global_meminfo()));
    // Fill the page with crap.
    addr_t virt_frame = phys2virt(frame);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint32_t); ++i) {
      ((uint32_t*)virt_frame)[i] = 0xCAFEBABE;
    }
  }

  return frame;
}

// TODO(SMP): make these SMP-safe with a raw spinlock.
void NO_TSAN page_frame_free(phys_addr_t frame_addr) {
  KASSERT(is_page_aligned(frame_addr));

  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Fill the page with crap.
    addr_t virt_frame = phys2virt(frame_addr);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint32_t); ++i) {
      ((uint32_t*)virt_frame)[i] = 0xDEADBEEF;
    }
  }

  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(stack_idx < stack_entries);
  page_alloc_metadata_t* md = get_page_md(frame_addr);
  KASSERT(md->allocated == true);
  md->allocated = false;
#if ENABLE_KMALLOC_HEAP_PROFILE
  tracetbl_unref(md->trace);
  md->trace = -1;
#endif

  if (ENABLE_KERNEL_SAFETY_NETS) {
    KASSERT_DBG(frame_addr < meminfo_mainmem_end(get_global_meminfo()));
    // Check that the page frame isn't already free.
    for (size_t i = 0; i < stack_idx; ++i) {
      KASSERT(free_frame_stack[i] != frame_addr);
    }
  }

  free_frame_stack[stack_idx++] = frame_addr;
  POP_INTERRUPTS();
}

void page_frame_free_nocheck(phys_addr_t frame_addr) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(is_page_aligned(frame_addr));
  KASSERT(stack_idx < stack_entries);
  page_alloc_metadata_t* md = get_page_md(frame_addr);
  KASSERT(md->allocated == true);
  md->allocated = false;
#if ENABLE_KMALLOC_HEAP_PROFILE
  tracetbl_unref(md->trace);
  md->trace = -1;
#endif

  free_frame_stack[stack_idx++] = frame_addr;
  POP_INTERRUPTS();
}

phys_addr_t page_frame_dma_alloc(size_t pages) {
  PUSH_AND_DISABLE_INTERRUPTS();
  if (pages == 0 || pages > DMA_RESERVED_FRAMES - dma_reserved_first_free_idx) {
    POP_INTERRUPTS();
    return 0;
  }
  const phys_addr_t result =
      dma_reserved_first_frame + dma_reserved_first_free_idx * PAGE_SIZE;
  dma_reserved_first_free_idx += pages;
  page_alloc_metadata_t* md = get_page_md(result);
  KASSERT(md->allocated == false);
  md->allocated = true;
#if ENABLE_KMALLOC_HEAP_PROFILE
  addr_t stack_trace[32];
  const int stack_trace_len = get_stack_trace(stack_trace, 32);
  KASSERT_DBG(stack_trace_len > 3);
  md->trace = tracetbl_put(stack_trace, stack_trace_len);
#endif
  POP_INTERRUPTS();
  return result;
}

size_t page_frame_allocated_pages(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  size_t result = stack_entries - stack_idx;
  POP_INTERRUPTS();
  return result;
}

void page_frame_log_profile(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  for (size_t i = 0; i < g_page_md_entries; ++i) {
    if (!g_page_md[i].allocated) continue;

    klogf(" %d: %d [%d: %d] @", 1, PAGE_SIZE, 1, PAGE_SIZE);
#if ENABLE_KMALLOC_HEAP_PROFILE
      addr_t stack_trace[TRACETBL_MAX_TRACE_LEN];
      int len = tracetbl_get(g_page_md[i].trace, stack_trace);
      if (len < 0) {
        klog(" ??");
      } else {
        for (int j = 0; j < len; ++j) {
          klogf(" %#" PRIxADDR, stack_trace[j]);
        }
      }
#endif
      klog("\n");
  }
  POP_INTERRUPTS();
}
