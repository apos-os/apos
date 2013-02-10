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

#include "dev/block_cache.h"

#include "common/debug.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "kmalloc.h"
#include "memory.h"
#include "page_alloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"

#define BLOCKS_PER_PAGE (PAGE_SIZE / BLOCK_CACHE_BLOCK_SIZE)
#define DEFAULT_CACHE_SIZE 100

static int g_size = 0;
static int g_initialized = 0;
static int g_max_size = DEFAULT_CACHE_SIZE;

static htbl_t g_table;

// A cache entry.
// TODO(aoates): we could probably stuff this all into a single uint32_t.
typedef struct {
  void* block;
  int pin_count;

  int initialized;
  kthread_queue_t init_wait_queue;
} cache_entry_t;

// TODO(aoates): make this flexible.
#define FREE_BLOCK_STACK_SIZE DEFAULT_CACHE_SIZE
static uint32_t g_free_block_stack[FREE_BLOCK_STACK_SIZE];
static int g_free_block_stack_idx = 0;  // First free entry.

// Acquire more free blocks and add them to the free block stack.
static void get_more_free_blocks() {
  KASSERT(FREE_BLOCK_STACK_SIZE - g_free_block_stack_idx > BLOCKS_PER_PAGE);
  const uint32_t phys_page = page_frame_alloc();
  if (phys_page == 0x0) {
    return;
  }
  const uint32_t page = phys2virt(phys_page);

  KASSERT(PAGE_SIZE % BLOCK_CACHE_BLOCK_SIZE == 0);
  for (int i = 0; i < BLOCKS_PER_PAGE; ++i) {
    g_free_block_stack[g_free_block_stack_idx++] =
        page + BLOCK_CACHE_BLOCK_SIZE * i;
  }
}

// Return a free block for a new cache entry.
static void* get_free_block() {
  if (g_free_block_stack_idx == 0) {
    get_more_free_blocks();
  }

  // If we can't get any new blocks, we must be done.
  if (g_free_block_stack_idx == 0) {
    return 0x0;
  }
  const uint32_t block = g_free_block_stack[--g_free_block_stack_idx];
  return (void*)block;
}

// Return a free block to the stack.
static void put_free_block(void* block) {
  if (g_free_block_stack_idx == FREE_BLOCK_STACK_SIZE) {
    klogf("WARNING: dropping free block because the free block "
          "cache is full!\n");
    // TODO(aoates): try to compact free block stack and free pages, and/or
    // resize the stack to fit.
    return;
  }
  if (ENABLE_KERNEL_SAFETY_NETS) {
    kmemset(block, 0xB, BLOCK_CACHE_BLOCK_SIZE);
  }
  g_free_block_stack[g_free_block_stack_idx++] = (uint32_t)block;
}

static uint32_t block_hash(dev_t dev, int offset) {
  // TODO(aoates): do we want to make a guaranteed-unique key by stuffing the
  // dev and offset into a uint32_t instead of hashing?
  uint32_t h = fnv_hash_array(&dev, sizeof(dev_t));
  h = fnv_hash_concat(h, fnv_hash(offset));
  return h;
}

void* block_cache_get(dev_t dev, int offset) {
  if (!g_initialized) {
    htbl_init(&g_table, g_max_size * 2);
    g_initialized = 1;
  }
  if (g_size >= g_max_size) {
    return 0x0;
  }

  const uint32_t h = block_hash(dev, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    // Get a new free block, fill it, and return it.
    void* block = get_free_block();
    if (!block) {
      return 0x0;
    }

    g_size++;
    cache_entry_t* entry = (cache_entry_t*)kmalloc(sizeof(cache_entry_t));
    entry->block = block;
    entry->pin_count = 1;
    entry->initialized = 0;
    kthread_queue_init(&entry->init_wait_queue);

    // Put the uninitialized entry into the table.
    htbl_put(&g_table, h, entry);

    // Read data from the block device into the cache.
    block_dev_t* bd = dev_get_block(dev);
    KASSERT(bd != 0x0);
    KASSERT(BLOCK_CACHE_BLOCK_SIZE % bd->sector_size == 0);
    const uint32_t sector = offset * BLOCK_CACHE_BLOCK_SIZE / bd->sector_size;
    // Note: this may block.
    const int result =
        bd->read(bd, sector, entry->block, BLOCK_CACHE_BLOCK_SIZE);
    KASSERT(result == BLOCK_CACHE_BLOCK_SIZE);

    entry->initialized = 1;
    scheduler_wake_all(&entry->init_wait_queue);

    return entry->block;
  } else {
    cache_entry_t* entry = (cache_entry_t*)tbl_value;
    entry->pin_count++;
    if (!entry->initialized) {
      scheduler_wait_on(&entry->init_wait_queue);
    }
    KASSERT(entry->initialized);
    return entry->block;
  }
}

void block_cache_put(dev_t dev, int offset) {
  KASSERT(g_initialized);

  const uint32_t h = block_hash(dev, offset);
  void* tbl_value = 0x0;
  KASSERT(htbl_get(&g_table, h, &tbl_value) == 0);

  cache_entry_t* entry = (cache_entry_t*)tbl_value;
  entry->pin_count--;
  if (entry->pin_count == 0) {
    g_size--;

    // TODO(aoates): make sure we synchronize with threads that may be trying to
    // get() this block simultaneously.
    // TODO(aoates): don't actually remove the block from the cache until we
    // need to reclaim memory.
    KASSERT(htbl_remove(&g_table, h) == 0);

    // Write the data back to disk.  This may block.
    block_dev_t* bd = dev_get_block(dev);
    const uint32_t sector = offset * BLOCK_CACHE_BLOCK_SIZE / bd->sector_size;
    const int result =
        bd->write(bd, sector, entry->block, BLOCK_CACHE_BLOCK_SIZE);
    KASSERT(result == BLOCK_CACHE_BLOCK_SIZE);

    put_free_block(entry->block);
    kfree(entry);
  }
}

int block_cache_get_pin_count(dev_t dev, int offset) {
  if (!g_initialized) {
    return 0;
  }

  const uint32_t h = block_hash(dev, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    return 0;
  }

  return ((cache_entry_t*)tbl_value)->pin_count;
}

void block_cache_set_size(int blocks) {
  g_max_size = blocks;
  // TODO
}
