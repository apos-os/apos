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

#include <stddef.h>

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
#include "proc/sleep.h"

#define BLOCKS_PER_PAGE (PAGE_SIZE / BLOCK_CACHE_BLOCK_SIZE)
#define DEFAULT_CACHE_SIZE 2000

static int g_size = 0;
static int g_initialized = 0;
static int g_max_size = DEFAULT_CACHE_SIZE;

static htbl_t g_table;

// Lists of cache entries.
struct cache_entry;
typedef struct {
  struct cache_entry* prev;
  struct cache_entry* next;
} cache_entry_link_t;

typedef struct {
  struct cache_entry* head;
  struct cache_entry* tail;
} cache_entry_list_t;

// A cache entry.
// TODO(aoates): we could probably stuff this all into a single uint32_t.
typedef struct cache_entry {
  dev_t dev;
  uint32_t offset;
  void* block;
  int pin_count;

  // Link on the flush queue and LRU queue.
  cache_entry_link_t flushq;
  cache_entry_link_t lruq;

  // Set to 1 when the entry is flushed to disk, and to 0 when the entry is
  // taken by a thread.
  uint8_t flushed;
  uint8_t flushing;

  int initialized;
  kthread_queue_t wait_queue;  // Threads waiting for init or flush.
} cache_entry_t;

// TODO(aoates): make this flexible.
#define FREE_BLOCK_STACK_SIZE DEFAULT_CACHE_SIZE
static uint32_t g_free_block_stack[FREE_BLOCK_STACK_SIZE];
static int g_free_block_stack_idx = 0;  // First free entry.

// Queue of cache entries that need to be flushed.
static cache_entry_list_t g_flush_queue = {0x0, 0x0};

// LRU queue of cache entries that *might* be freeable.
static cache_entry_list_t g_lru_queue = {0x0, 0x0};

static inline void init_link(cache_entry_link_t* link) {
  link->prev = link->next = 0x0;
}

// TODO(aoates): move this list stuff to a common place where others can use it.
static inline cache_entry_link_t* get_link(cache_entry_t* entry,
                                           size_t link_offset) {
  return (cache_entry_link_t*)((void*)entry + link_offset);
}

static void _cache_entry_push(cache_entry_list_t* list,
                              cache_entry_t* entry,
                              size_t link_offset) {
  cache_entry_link_t* link = get_link(entry, link_offset);
  KASSERT_DBG(link->prev == 0x0);
  KASSERT_DBG(link->next == 0x0);
  if (list->head == 0x0) {
    KASSERT_DBG(list->tail == 0x0);
    list->head = list->tail = entry;
  } else {
    KASSERT_DBG(list->tail != 0x0);
    link->prev = list->tail;
    cache_entry_link_t* list_tail_link = get_link(list->tail, link_offset);
    list_tail_link->next = entry;
    list->tail = entry;
  }
}
#define cache_entry_push(list, entry, link_name) \
    _cache_entry_push(list, entry, offsetof(cache_entry_t, link_name))

static cache_entry_t* _cache_entry_pop(cache_entry_list_t* list,
                                       size_t link_offset) {
  if (list->head == 0x0) {
    KASSERT_DBG(list->tail == 0x0);
    return 0x0;
  } else {
    cache_entry_t* result = list->head;
    cache_entry_link_t* link = get_link(result, link_offset);
    KASSERT_DBG(link->prev == 0x0);
    if (link->next != 0x0) {
      KASSERT_DBG(list->tail != result);
      cache_entry_link_t* link_next_link = get_link(link->next, link_offset);
      link_next_link->prev = 0x0;
      list->head = link->next;
      link->next = 0x0;
    } else {
      KASSERT_DBG(list->tail == list->head);
      list->tail = list->head = 0x0;
    }
    return result;
  }
}
#define cache_entry_pop(list, link_name) \
    _cache_entry_pop(list, offsetof(cache_entry_t, link_name))

static void _cache_entry_remove(cache_entry_list_t* list,
                                cache_entry_t* entry,
                                size_t link_offset) {
  cache_entry_link_t* link = get_link(entry, link_offset);
  KASSERT_DBG(list->head != 0x0);
  KASSERT_DBG(list->tail != 0x0);
  if (list->head == entry) {
    _cache_entry_pop(list, link_offset);
  } else if (list->tail == entry) {
    KASSERT_DBG(link->next == 0x0);
    KASSERT_DBG(link->prev != 0x0);
    list->tail = link->prev;
    KASSERT_DBG(list->tail != 0x0);
    cache_entry_link_t* list_tail_link = get_link(list->tail, link_offset);
    KASSERT_DBG(list_tail_link->next == entry);
    list_tail_link->next = 0x0;
    link->prev = 0x0;
  } else {
    KASSERT_DBG(link->prev != 0x0);
    KASSERT_DBG(link->next != 0x0);
    cache_entry_link_t* prev_link = get_link(link->prev, link_offset);
    cache_entry_link_t* next_link = get_link(link->next, link_offset);
    prev_link->next = link->next;
    next_link->prev = link->prev;
    link->prev = link->next = 0x0;
  }
}
#define cache_entry_remove(list, entry, link_name) \
    _cache_entry_remove(list, entry, offsetof(cache_entry_t, link_name))

static int _cache_entry_on_list(cache_entry_t* entry,
                                size_t link_offset) {
  cache_entry_link_t* link = get_link(entry, link_offset);
  return link->next != 0x0 || link->prev != 0x0;
}
#define cache_entry_on_list(entry, link_name) \
    _cache_entry_on_list(entry, offsetof(cache_entry_t, link_name))

#define cache_entry_next(entry, link_name) (entry)->link_name.next

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

// Flush the given cache entry to disk.
static void flush_cache_entry(cache_entry_t* entry) {
  // Write the data back to disk.  This may block.
  entry->flushing = 1;
  block_dev_t* bd = dev_get_block(entry->dev);
  const uint32_t sector =
      entry->offset * BLOCK_CACHE_BLOCK_SIZE / bd->sector_size;
  const int result =
      bd->write(bd, sector, entry->block, BLOCK_CACHE_BLOCK_SIZE);
  KASSERT(result == BLOCK_CACHE_BLOCK_SIZE);
  entry->flushing = 0;
  entry->flushed = 1;
  scheduler_wake_all(&entry->wait_queue);
}

// The flush thread that works through the flush queue, flushing cache entries
// and sleeping.
static kthread_t g_flush_queue_thread;
static void* flush_queue_thread(void* arg) {
  const int kSleepMs = 5000;
  const int kMaxFlushesPerCycle = 1000;
  while (1) {
    ksleep(kSleepMs);
    int flushed = 0;
    while (flushed < kMaxFlushesPerCycle) {
      cache_entry_t* entry = cache_entry_pop(&g_flush_queue, flushq);
      if (!entry) break;
      flush_cache_entry(entry);
      flushed++;
    }
    if (flushed > 0)
      klogf("<block cache flushed %d entries>\n", flushed);
  }
  return 0x0;
}

// Remove the given (flushed and unpinned) cache entry from the table, release
// it's block, and free the entry object.
static void free_cache_entry(cache_entry_t* entry) {
  KASSERT_DBG(cache_entry_on_list(entry, flushq) == 0);
  KASSERT_DBG(cache_entry_on_list(entry, lruq) == 0);
  KASSERT_DBG(entry->pin_count == 0);
  KASSERT_DBG(entry->flushed);

  //klogf("<block cache free block %d>\n", entry->offset);
  g_size--;
  const uint32_t h = block_hash(entry->dev, entry->offset);
  KASSERT(htbl_remove(&g_table, h) == 0);
  put_free_block(entry->block);
  kfree(entry);
}

// Go through the cache and look for unpinned entries we can flush.
// TODO(aoates): use some sort of LRU mechanism to decide what to free.
static void maybe_free_cache_space() {
  const int kMaxEntriesFreed = 1;
  cache_entry_t* entry = g_lru_queue.head;
  int entries_freed = 0;
  while (entry && entries_freed < kMaxEntriesFreed) {
    KASSERT(entry->pin_count == 0);
    cache_entry_t* next = cache_entry_next(entry, lruq);
    if (entry->flushed) {
      KASSERT_DBG(!cache_entry_on_list(entry, flushq));
      cache_entry_remove(&g_lru_queue, entry, lruq);

      // No-one else has it, so free it.
      free_cache_entry(entry);
      entries_freed++;
    }
    entry = next;
  }

  // If nothing is already flushed, find an unpinned entry and force flush it.
  entry = g_lru_queue.head;
  while (entry && entries_freed < kMaxEntriesFreed) {
    KASSERT(entry->pin_count == 0);
    if (cache_entry_on_list(entry, flushq)) {
      cache_entry_remove(&g_flush_queue, entry, flushq);
      cache_entry_remove(&g_lru_queue, entry, lruq);

      flush_cache_entry(entry);

      // flush_cache_entry blocks, so we have to verify that no one took it in
      // the meantime.
      if (entry->flushed && entry->pin_count == 0) {
        // No-one else has it, so free it.
        free_cache_entry(entry);
        entries_freed++;
      }
    }
    entry = cache_entry_next(entry, lruq);
  }

  // TODO(aoates): if something is currently flushing, block for it to finish.
}

static void init_block_cache() {
  KASSERT(!g_initialized);
  htbl_init(&g_table, g_max_size * 2);
  KASSERT(kthread_create(&g_flush_queue_thread, &flush_queue_thread, 0x0) != 0);
  scheduler_make_runnable(g_flush_queue_thread);
  g_initialized = 1;
}

void* block_cache_get(dev_t dev, int offset) {
  //if (offset == 1) klogf("block_cache_get(block=1)\n");
  if (!g_initialized) {
    init_block_cache();
  }
  if (g_size >= g_max_size) {
    maybe_free_cache_space();
    if (g_size >= g_max_size) {
      return 0x0;
    }
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
    entry->dev = dev;
    entry->offset = offset;
    entry->block = block;
    entry->pin_count = 1;
    entry->initialized = 0;
    entry->flushed = 0;
    entry->flushing = 0;
    init_link(&entry->flushq);
    init_link(&entry->lruq);
    kthread_queue_init(&entry->wait_queue);

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
    scheduler_wake_all(&entry->wait_queue);

    return entry->block;
  } else {
    cache_entry_t* entry = (cache_entry_t*)tbl_value;
    entry->pin_count++;
    if (!entry->initialized) {
      scheduler_wait_on(&entry->wait_queue);
    }
    KASSERT(entry->initialized);
    if (cache_entry_on_list(entry, lruq)) {
      KASSERT(entry->pin_count == 1);
      cache_entry_remove(&g_lru_queue, entry, lruq);
    }
    entry->flushed = 0;
    return entry->block;
  }
}

void block_cache_put(dev_t dev, int offset) {
  //if (offset == 1) klogf("block_cache_put(block=1)\n");
  KASSERT(g_initialized);

  const uint32_t h = block_hash(dev, offset);
  void* tbl_value = 0x0;
  KASSERT(htbl_get(&g_table, h, &tbl_value) == 0);

  cache_entry_t* entry = (cache_entry_t*)tbl_value;
  KASSERT(entry->dev.major == dev.major && entry->dev.minor == dev.minor);
  entry->pin_count--;

  // The block needs to be flushed, if it's not already scheduled for one.
  entry->flushed = 0;
  if (!cache_entry_on_list(entry, flushq)) {
    cache_entry_push(&g_flush_queue, entry, flushq);
  }

  KASSERT(!cache_entry_on_list(entry, lruq));
  if (entry->pin_count == 0) {
    cache_entry_push(&g_lru_queue, entry, lruq);
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

void block_cache_clear_unpinned() {
  // Flush everything on the flush queue.
  cache_entry_t* entry = cache_entry_pop(&g_flush_queue, flushq);
  while (entry) {
    flush_cache_entry(entry);
    entry = cache_entry_pop(&g_flush_queue, flushq);
  }

  // Clear the LRU queue.
  entry = cache_entry_pop(&g_lru_queue, lruq);
  while (entry) {
    KASSERT_DBG(entry->pin_count == 0);
    KASSERT_DBG(entry->flushed);
    KASSERT_DBG(!cache_entry_on_list(entry, flushq));
    free_cache_entry(entry);
    entry = cache_entry_pop(&g_lru_queue, lruq);
  }
}

typedef struct {
  int total;
  int flushq;
  int flushing;
  int flushed;
  int lru;
  int pinned;
  int total_pins;
} stats_t;
void htbl_iterate(htbl_t* tbl, void (*func)(void*, uint32_t, void*), void* arg);
static void stats_counter_func(void* arg, uint32_t key, void* value) {
  stats_t* stats = (stats_t*)arg;
  cache_entry_t* entry = (cache_entry_t*)value;
  stats->total++;
  if (cache_entry_on_list(entry, flushq))
    stats->flushq++;
  else if (entry->pin_count == 0 && entry->flushed == 0)
    stats->flushing++;
  if (entry->flushed)
    stats->flushed++;
  if (cache_entry_on_list(entry, lruq))
    stats->lru++;
  if (entry->pin_count > 0) {
    stats->pinned++;
    stats->total_pins += entry->pin_count;
  }
}
void block_cache_log_stats() {
  stats_t stats;
  kmemset(&stats, 0, sizeof(stats_t));
  htbl_iterate(&g_table, &stats_counter_func, &stats);
  klogf("Block cache stats:\n");
  klogf("  total entries: %d\n", stats.total);
  klogf("         pinned: %d\n", stats.pinned);
  klogf("     total pins: %d\n", stats.total_pins);
  klogf("      on flushq: %d\n", stats.flushq);
  klogf("         on lru: %d\n", stats.lru);
  klogf("        flushed: %d\n", stats.flushed);
  klogf("       flushing: %d\n", stats.flushing);
}
