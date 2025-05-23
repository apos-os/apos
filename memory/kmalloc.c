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

#include "memory/kmalloc.h"

#include <stdbool.h>
#include <stdint.h>

#include "arch/dev/interrupts.h"
#include "arch/memory/page_map.h"
#include "arch/proc/stack_trace.h"
#include "common/attributes.h"
#include "common/debug.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/math.h"
#include "common/stack_trace_table.h"
#include "memory/allocator.h"
#include "memory/kmalloc-internal.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"
#include "proc/spinlock.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_access.h"
#include "sanitizers/tsan/tsan_sync.h"
#endif

#define KLOG(...) klogfm(KL_KMALLOC, __VA_ARGS__)

#define KMALLOC_PRE_ALLOC_PAGES 5

static bool g_initialized = false;

static kspinlock_intsafe_t g_kmalloc_mu =
    KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC;

// Global block list.
static block_t* g_block_list GUARDED_BY(g_kmalloc_mu) = 0;

// The first address that has not had a page allocated to it (ala brk()).
static addr_t g_kmalloc_top GUARDED_BY(g_kmalloc_mu);

// Root process vm_area_t for the heap.
static vm_area_t g_root_heap_vm_area;

static int g_test_mode = 0;

// Ensure all addresses in the range [ptr, ptr + len) are backed by pages.
static void preallocate_block(void* ptr, size_t len) REQUIRES(g_kmalloc_mu) {
  addr_t end = (addr_t)ptr + len;
  while (end > g_kmalloc_top) {
    phys_addr_t phys_addr = page_frame_alloc();
    page_frame_map_virtual(g_kmalloc_top, phys_addr, MEM_PROT_ALL,
                           MEM_ACCESS_KERNEL_ONLY, MEM_GLOBAL);
    g_kmalloc_top += PAGE_SIZE;
  }
}

static void init_block(block_t* b) REQUIRES(g_kmalloc_mu) {
  preallocate_block(b, sizeof(block_t));
  b->magic = KALLOC_MAGIC;
  b->free = true;
  b->length = 0;
  b->prev = 0;
  b->next = 0;
  kmemset(b->_buf, 0xAA, KMALLOC_SAFE_BUFFER);
}

void kmalloc_init(void) {
  const memory_info_t* meminfo = get_global_meminfo();
  KASSERT(proc_current() != 0x0);

  if (!g_test_mode) {
    KASSERT(!g_initialized);
    KASSERT(proc_current()->id == 0);

    // First we have to set up the vm_area_t in the current process for our heap
    // region.  We touch the memory after this, and this mapping must exist for
    // the page fault handler not to bork.
    vm_create_kernel_mapping(&g_root_heap_vm_area, meminfo->heap.base,
                             meminfo->heap.len, true /* allow_allocation */);
  }

  // Initialize the free list to one giant block consisting of the entire heap.
  KASSERT(meminfo->heap_size_max <= meminfo->heap.len);
  KASSERT(meminfo->heap_size_max % PAGE_SIZE == 0);
  KASSERT(meminfo->heap_size_max >= 1024 * 1024);
  kspin_lock_early(&g_kmalloc_mu);
  g_kmalloc_top = meminfo->heap.base;
  block_t* head = (block_t*)meminfo->heap.base;
  init_block(head);
  head->length = meminfo->heap_size_max - sizeof(block_t);
  g_block_list = head;
  kspin_unlock_early(&g_kmalloc_mu);
  g_initialized = 1;
}

// Fill the given block with a repeating pattern.
static void NO_TSAN fill_buffer(uint8_t* buf, size_t n, uint32_t pattern) {
#if ENABLE_TSAN
  tsan_check_range(0, (addr_t)buf, n, TSAN_ACCESS_WRITE);
#endif
  uint32_t i = 0;
  uint32_t i2 = 0;
  while (i < n) {
    buf[i] = ((uint8_t*)&pattern)[i2];
    i2 = (i2 + 1) % 4;
    i++;
  }
}

// Fill the given block's data with a repeating pattern.
static void fill_block(block_t* b, uint32_t pattern) {
  fill_buffer(b->data, b->length, pattern);
}

// Takes a block and a required size, and (if it's large enough), splits the
// block into two blocks, adding them both to the block list as needed.
static block_t* split_block(block_t* b, size_t n) REQUIRES(g_kmalloc_mu) {
  KASSERT(b->length >= n);
  if (b->length < n + sizeof(block_t) + KALLOC_MIN_BLOCK_SIZE) {
    return b;
  }

  block_t* new_block = (block_t*)((uint8_t*)b + sizeof(block_t) + n);
  init_block(new_block);
  new_block->free = true;
  new_block->length = b->length - sizeof(block_t) - n;
  new_block->prev = b;
  new_block->next = b->next;

  b->length = n;
  if (b->next) {
    b->next->prev = new_block;
  }
  b->next = new_block;

  return b;
}

// Given two adjacent blocks, merge them, returning the new (unified) block.
static inline block_t* merge_adjancent_blocks(block_t* a, block_t* b)
    REQUIRES(g_kmalloc_mu) {
  KASSERT(a->free);
  KASSERT(b->free);
  KASSERT(BLOCK_END(a) == BLOCK_START(b));
  KASSERT(a->next == b);
  KASSERT(b->prev == a);

  if (b->next) {
    b->next->prev = a;
  }
  a->next = b->next;
  a->length += BLOCK_SIZE(b);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    // Clobber the header of b.
    fill_buffer((uint8_t*)b, sizeof(block_t), 0xDEADBEEF);
  }
  return a;
}

// Given a (free) block, merge it with the previous and/or next blocks in the
// block list, if they're also free.  Returns a pointer to the new block.
static block_t* merge_block(block_t* b) REQUIRES(g_kmalloc_mu) {
  KASSERT(b->free);

  if (b->prev && b->prev->free) {
    if (BLOCK_END(b->prev) == BLOCK_START(b)) {
      b = merge_adjancent_blocks(b->prev, b);
    }
  }

  if (b->next && b->next->free) {
    if (BLOCK_END(b) == BLOCK_START(b->next)) {
      b = merge_adjancent_blocks(b, b->next);
    }
  }

  return b;
}

static inline ALWAYS_INLINE size_t default_align(size_t n) {
  switch (n) {
    case 1:
      return 1;
    case 2:
      return 2;
    case 3:
    case 4:
      return 4;
    default:
      return sizeof(addr_t);
  }
}

void* kmalloc(size_t n) {
  return kmalloc_aligned(n, default_align(n));
}

void* kmalloc_alloc(void* arg, size_t n, size_t alignment) {
  KASSERT_DBG(arg == NULL);
  n += KMALLOC_SAFE_BUFFER;
#if ENABLE_KMALLOC_HEAP_PROFILE
  addr_t stack_trace[32];
  const int stack_trace_len = get_stack_trace(stack_trace, 32);
  KASSERT_DBG(stack_trace_len > 3);
  const trace_id_t stack_trace_id = tracetbl_put(stack_trace, stack_trace_len);
#endif

  kspin_lock_early(&g_kmalloc_mu);
  // Try to find a free block that's big enough.
  block_t* cblock = g_block_list;
  addr_t block_addr, next_aligned;
  while (cblock) {
    if (cblock->free && cblock->length >= n) {
      block_addr = (addr_t)&cblock->data;
      if (block_addr % alignment == 0) break;  // Fast path.

      // TODO(aoates): check for overflow in these various calculations.
      next_aligned = alignment * ceiling_div(
          block_addr + sizeof(block_t) + KALLOC_MIN_BLOCK_SIZE, alignment);
      if (block_addr + cblock->length >= next_aligned + n) break;
    }
    cblock = cblock->next;
  }

  if (!cblock || cblock->length < n) {
    kspin_unlock_early(&g_kmalloc_mu);
    return 0;
  }

  KASSERT(cblock->free);
  KASSERT(cblock->length >= n);

  if (block_addr % alignment != 0) {
    block_t* extra = split_block(
        cblock, next_aligned - (block_addr + sizeof(block_t)));
    cblock = extra->next;

    KASSERT_DBG((addr_t)&cblock->data % alignment == 0);
    KASSERT_DBG((addr_t)&cblock->data == next_aligned);

    block_addr = next_aligned;
  }

  cblock->free = false;
  cblock = split_block(cblock, n);
#if ENABLE_KMALLOC_HEAP_PROFILE
  cblock->stack_trace = stack_trace_id;
#endif

  // No need to preallocate here --- split_block() calls preallocate_block() on
  // the next block, ensuring this entire block is itself preallocated as well.
  kspin_unlock_early(&g_kmalloc_mu);

  if (ENABLE_KERNEL_SAFETY_NETS) {
    fill_block(cblock, 0xAAAAAAAA);
  }
  return (void*)(&cblock->data);
}

void kfree(void* x) {
  block_t* b = (block_t*)((uint8_t*)x - sizeof(block_t));
  KASSERT(b->magic == KALLOC_MAGIC);
  KASSERT(b->free == false);
  bool bad = false;
  for (int i = 0; i < KMALLOC_SAFE_BUFFER; ++i) {
    if (b->_buf[i] != 0xAA) {
      KLOG(ERROR,
           "Buffer underflow detected at address 0x%" PRIxADDR
           "(allocated addr 0x%" PRIxADDR ", offset %d)\n",
           (intptr_t)&b->_buf[i], (intptr_t)x,
           -KMALLOC_SAFE_BUFFER + i);
      bad = true;
      break;
    }
  }
  const uint8_t* post_buf =
      (uint8_t*)&b->data + (b->length - KMALLOC_SAFE_BUFFER);
  for (int i = 0; i < KMALLOC_SAFE_BUFFER; ++i) {
    if (post_buf[i] != 0xAA) {
      KLOG(ERROR,
           "Buffer overflow detected at address 0x%" PRIxADDR
           "(allocated addr 0x%" PRIxADDR ", offset %d)\n",
           (intptr_t)&post_buf[i], (intptr_t)x,
           (int)b->length + i);
      bad = true;
      break;
    }
  }
  if (bad) {
#if ENABLE_KMALLOC_HEAP_PROFILE
    addr_t trace[TRACETBL_MAX_TRACE_LEN];
    int len = tracetbl_get(b->stack_trace, trace);
    KLOG(ERROR, "Block allocated at:\n");
    print_stack_trace(trace, len);
#endif
    die("Heap corruption");
  }
  if (ENABLE_KERNEL_SAFETY_NETS) {
    fill_block(b, 0xDEADBEEF);
  }
#if ENABLE_TSAN
  tsan_sync_free((addr_t)&b->data, b->length);
#endif

  kspin_lock_early(&g_kmalloc_mu);
  b->free = true;
#if ENABLE_KMALLOC_HEAP_PROFILE
  if (b->stack_trace >= 0) tracetbl_unref(b->stack_trace);
#endif
  merge_block(b);
  kspin_unlock_early(&g_kmalloc_mu);
}

void kmalloc_log_state(void) {
  KLOG(INFO, "kmalloc block list:\n");
  size_t total = 0;
  size_t free = 0;
  kspin_lock_early(&g_kmalloc_mu);
  block_t* cblock = g_block_list;
  while (cblock) {
    total += cblock->length + sizeof(block_t);
    if (cblock->free) {
      free += cblock->length;
    }
    KLOG(INFO, "  %p < free: %d len: 0x%" PRIxADDR " prev: %p next: %p >\n",
         cblock, cblock->free, cblock->length, cblock->prev, cblock->next);
    KLOG(DEBUG, "             < %x %x %x %x >\n",
         ((unsigned int*)(&cblock->data))[0],
         ((unsigned int*)(&cblock->data))[1],
         ((unsigned int*)(&cblock->data))[2],
         ((unsigned int*)(&cblock->data))[3]);

    cblock = cblock->next;
  }
  kspin_unlock_early(&g_kmalloc_mu);
  KLOG(INFO, "total memory: 0x%zx bytes (%zu MB)\n", total, total / 1024 / 1024);
  KLOG(INFO, "free memory: 0x%zx bytes (%zu MB)\n", free, free / 1024 / 1024);
}

void kmalloc_log_heap_profile(bool include_pages) {
  kspin_lock_early(&g_kmalloc_mu);
  size_t total_objects = 0, total_bytes = 0;

  block_t* cblock = g_block_list;
  while (cblock) {
    if (!cblock->free) {
      total_objects++;
      total_bytes += cblock->length;
    }
    cblock = cblock->next;
  }
  // Note: this is racy, as other pages could be allocated or freed between here
  // and when we actually list all the pages below.
  size_t pages_allocated = page_frame_allocated_pages();
  if (include_pages) {
    total_objects += pages_allocated;
    total_bytes += pages_allocated * PAGE_SIZE;
  }

  KLOG(INFO, "heap profile:  %zu:  %zu [  %zu:  %zu] @ heap/1\n",
       total_objects, total_bytes, total_objects, total_bytes);

  cblock = g_block_list;
  while (cblock) {
    if (!cblock->free) {
      KLOG(INFO, " %d: %" PRIuADDR " [%d: %" PRIuADDR "] @", 1, cblock->length,
           1, cblock->length);
#if ENABLE_KMALLOC_HEAP_PROFILE
      addr_t stack_trace[TRACETBL_MAX_TRACE_LEN];
      int len = tracetbl_get(cblock->stack_trace, stack_trace);
      if (len < 0) {
        KLOG(INFO, " ??");
      } else {
        for (int i = 0; i < len; ++i) {
          KLOG(INFO, " %#" PRIxADDR, stack_trace[i]);
        }
      }
#endif
      KLOG(INFO, "\n");
    }
    cblock = cblock->next;
  }

  if (include_pages) {
    page_frame_log_profile();
  }

  KLOG(INFO, "#### heap profile end ####\n");

  if (!include_pages) {
    KLOG(INFO, "Total pages allocated: %zu\n", pages_allocated);
  }

  kspin_unlock_early(&g_kmalloc_mu);
}

void kmalloc_enable_test_mode(void) {
  g_test_mode = 1;
}

block_t* kmalloc_internal_get_block_list(void) NO_THREAD_SAFETY_ANALYSIS {
  return g_block_list;
}

static void kfree_alloc(void* arg, void* ptr) {
  KASSERT_DBG(arg == NULL);
  return kfree(ptr);
}

allocator_t kDefaultAlloc = {
  &kmalloc_alloc,
  &kfree_alloc,
  NULL,
};
