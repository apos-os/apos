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

// Every memory block has the following structure:
// | free (8 bits) | length (32 bits) | prev (32 bits) | next (32 bits) | data (length bytes) |
// That is, a header with the block length (not including the header), a pointer
// to the next block in chain, and then the data.
//
// In general, blocks are passed around by pointers to the start of their
// headers.  When we give a block to (or take on from) a caller, we use a
// pointer to the data.
struct block {
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

// Allocates a fresh physical page from the page frame allocator, creates a
// block for it, inserts it into the block list, and returns it.
static block_t* kalloc_new_page() {
  uint32_t page = page_frame_alloc();
  kassert_msg(page, "out of memory in kmalloc");
  block_t* block = (block_t*)phys2virt(page);

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

  // TODO(aoates): split block.
  cblock->free = 0;
  return (void*)(&cblock->data);
}

void kmalloc_log_state() {
  klog("kmalloc block list:\n");
  block_t* cblock = g_block_list;
  while (cblock) {
    klog("  < free: ");
    klog(itoa(cblock->free));
    klog(" len: ");
    klog(itoa_hex(cblock->length));

    klog(" prev: ");
    klog(itoa_hex(cblock->prev));

    klog(" next: ");
    klog(itoa_hex(cblock->next));
    klog(" >\n");

    cblock = cblock->next;
  }
}
