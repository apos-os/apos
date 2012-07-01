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

#include "kmalloc.h"
#include "kmalloc-internal.h"

#include <stdint.h>

#include "common/klog.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory.h"
#include "page_alloc.h"

// Global block list.
static block_t* g_block_list = 0;

void kmalloc_init() {
  static block_t head;
  head.free = 0;
  head.prev = 0;
  head.next = 0;
  g_block_list = &head;
}

static void init_block(block_t* b) {
  b->magic = KALLOC_MAGIC;
  b->free = 1;
  b->length = 0;
  b->prev = 0;
  b->next = 0;
}

// Fill the given block with a repeating pattern.
static void fill_buffer(uint8_t* buf, uint32_t n, uint32_t pattern) {
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
static block_t* split_block(block_t* b, uint32_t n) {
  KASSERT(b->length >= n);
  if (b->length < n + sizeof(block_t) + KALLOC_MIN_BLOCK_SIZE) {
    return b;
  }

  block_t* new_block = (block_t*)((uint8_t*)b + sizeof(block_t) + n);
  init_block(new_block);
  new_block->free = 1;
  new_block->length = b->length - sizeof(block_t) - n;
  new_block->prev = b;
  new_block->next = b->next;

  b->length = n;
  b->next = new_block;

  return b;
}

// Given two adjacent blocks, merge them, returning the new (unified) block.
static block_t* merge_adjancent_blocks(block_t* a, block_t* b) {
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

  // Clobber the header of b.
  fill_buffer((uint8_t*)b, sizeof(block_t), 0xDEADBEEF);
  return a;
}

// Given a (free) block, merge it with the previous and/or next blocks in the
// block list, if they're also free.  Returns a pointer to the new block.
static block_t* merge_block(block_t* b) {
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

// Allocates a fresh physical page from the page frame allocator, creates a
// block for it, inserts it into the block list, and returns it.
static block_t* new_page() {
  uint32_t page = page_frame_alloc();
  kassert_msg(page, "out of memory in kmalloc");
  block_t* block = (block_t*)phys2virt(page);
  init_block(block);

  block->free = 1;
  block->length = PAGE_SIZE - sizeof(block_t);

  // Add it to the list.
  block_t* prev = g_block_list;
  block_t* cblock = g_block_list->next;
  while (cblock) {
    if (cblock != g_block_list && cblock > block) {
      break;
    }
    prev = cblock;
    cblock = cblock->next;
  }

  if (!cblock) {
    // Insert at end of list.
    prev->next = block;
    block->prev = prev;
    block->next = 0;
  } else {
    // Insert in between prev and cblock.
    KASSERT(prev->next == cblock);
    KASSERT(cblock->prev == prev);
    prev->next = block;
    block->prev = prev;
    block->next = cblock;
    cblock->prev = block;
  }

  fill_block(block, 0xDEADBEEF);
  merge_block(block);
  return block;
}

void* kmalloc(uint32_t n) {
  // Try to find a free block that's big enough.
  block_t* cblock = g_block_list;
  while (cblock) {
    if (cblock->free && cblock->length >= n) {
      break;
    }
    cblock = cblock->next;
  }

  if (!cblock) {
    cblock = new_page();
  }

  if (!cblock || cblock->length < n) {
    return 0;
  }

  KASSERT(cblock->free);
  KASSERT(cblock->length >= n);

  cblock->free = 0;
  cblock = split_block(cblock, n);

  fill_block(cblock, 0xAAAAAAAA);
  return (void*)(&cblock->data);
}

void kfree(void* x) {
  block_t* b = (block_t*)((uint8_t*)x - sizeof(block_t));
  KASSERT(b->magic == KALLOC_MAGIC);
  KASSERT(b->free == 0);
  b->free = 1;
  fill_block(b, 0xDEADBEEF);

  merge_block(b);
}

void kmalloc_log_state() {
  klog("kmalloc block list:\n");
  block_t* cblock = g_block_list;
  while (cblock) {
    klogf("  0x%x < free: %d len: 0x%x prev: 0x%x next: 0x%x >\n",
          cblock, cblock->free, cblock->length, cblock->prev, cblock->next);
    //klogf("             < %x %x %x %x >\n",
    //      ((uint32_t*)(&cblock->data))[0],
    //      ((uint32_t*)(&cblock->data))[1],
    //      ((uint32_t*)(&cblock->data))[2],
    //      ((uint32_t*)(&cblock->data))[3]);

    cblock = cblock->next;
  }
}

block_t* kmalloc_internal_get_block_list() {
  return g_block_list;
}
