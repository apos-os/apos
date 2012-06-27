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

#include <stdint.h>

#include "common/klog.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory.h"
#include "page_alloc.h"

// Don't bother splitting a block if it'll be smaller than this (bytes).
#define KALLOC_MIN_BLOCK_SIZE 8

#define KALLOC_MAGIC 0xAB

// Every memory block has the following structure:
// | free (8 bits) | length (32 bits) | prev (32 bits) | next (32 bits) | data (length bytes) |
// That is, a header with the block length (not including the header), a pointer
// to the next block in chain, and then the data.
//
// In general, blocks are passed around by pointers to the start of their
// headers.  When we give a block to (or take on from) a caller, we use a
// pointer to the data.
struct block {
  uint8_t magic;
  uint8_t free;
  uint32_t length;
  struct block* prev;
  struct block* next;
  uint8_t data[0];
};
typedef struct block block_t;

// Global block list.
block_t* g_block_list = 0;

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

// Allocates a fresh physical page from the page frame allocator, creates a
// block for it, inserts it into the block list, and returns it.
static block_t* kalloc_new_page() {
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
    kassert(prev->next == cblock);
    kassert(cblock->prev == prev);
    prev->next = block;
    block->prev = prev;
    block->next = cblock;
    cblock->prev = block;
  }

  // TODO(aoates): merge block.

  return block;
}

// Takes a block and a required size, and (if it's large enough), splits the
// block into two blocks, adding them both to the block list as needed.
static block_t* kalloc_split_block(block_t* b, uint32_t n) {
  kassert(b->length >= n);
  if (b->length < n + sizeof(block_t) + KALLOC_MIN_BLOCK_SIZE) {
    return b;
  }

  block_t* new_block = (uint8_t*)b + sizeof(block_t) + n;
  init_block(new_block);
  new_block->free = 1;
  new_block->length = b->length - sizeof(block_t) - n;
  new_block->prev = b;
  new_block->next = b->next;

  b->length = n;
  b->next = new_block;

  return b;
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
    cblock = kalloc_new_page();
  }

  if (!cblock || cblock->length < n) {
    return 0;
  }

  kassert(cblock->free);
  kassert(cblock->length >= n);

  cblock->free = 0;
  cblock = kalloc_split_block(cblock, n);
  return (void*)(&cblock->data);
}

void kfree(void* x) {
  block_t* b = (block_t*)((uint8_t*)x - sizeof(block_t));
  kassert(b->magic == KALLOC_MAGIC);
  b->free = 1;

  // TODO(aoates): merge blocks.
}

void kmalloc_log_state() {
  klog("kmalloc block list:\n");
  block_t* cblock = g_block_list;
  while (cblock) {
    klogf("  0x%x < free: %d len: 0x%x prev: 0x%x next: 0x%x >\n",
          cblock, cblock->free, cblock->length, cblock->prev, cblock->next);

    cblock = cblock->next;
  }
}
