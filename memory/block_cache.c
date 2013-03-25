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

#include "memory/block_cache.h"

#include <stddef.h>

#include "common/errno.h"
#include "common/debug.h"
#include "common/list.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/page_alloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"

#define BLOCKS_PER_PAGE (PAGE_SIZE / BLOCK_CACHE_BLOCK_SIZE)
#define DEFAULT_CACHE_SIZE 2000

// If set, then all data structures will be frequently checked for consistency.
#define SLOW_CONSISTENCY_CHECKS 0

static int g_size = 0;
static int g_initialized = 0;
static int g_max_size = DEFAULT_CACHE_SIZE;

static htbl_t g_table;

// A cache entry.
typedef struct bc_entry_internal {
  bc_entry_t pub;
  int pin_count;

  // Link on the flush queue and LRU queue.
  list_link_t flushq;
  list_link_t lruq;

  // Set to 1 when the entry is flushed to disk, and to 0 when the entry is
  // taken by a thread.
  uint8_t flushed;
  uint8_t flushing;

  int initialized;
  kthread_queue_t wait_queue;  // Threads waiting for init or flush.
} bc_entry_internal_t;

// TODO(aoates): make this flexible.
#define FREE_BLOCK_STACK_SIZE DEFAULT_CACHE_SIZE
static uint32_t g_free_block_stack[FREE_BLOCK_STACK_SIZE];
static int g_free_block_stack_idx = 0;  // First free entry.

// Queue of cache entries that need to be flushed.
static list_t g_flush_queue = {0x0, 0x0};

// LRU queue of cache entries that *might* be freeable.
static list_t g_lru_queue = {0x0, 0x0};

#define cache_entry_pop(list, link_name) \
    container_of(list_pop(list), bc_entry_internal_t, link_name)

#define cache_entry_next(entry, link_name) \
    container_of((entry)->link_name.next, bc_entry_internal_t, link_name)

#define cache_entry_head(list, link_name) \
    container_of((list).head, bc_entry_internal_t, link_name)

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

static uint32_t obj_hash(memobj_t* obj, int offset) {
  uint32_t array[3] = {obj->type, obj->id, offset};
  uint32_t h = fnv_hash_array(array, 3 * sizeof(uint32_t));
  return h;
}

// Basic sanity checks on a bc_entry_t.
static int entry_is_sane(bc_entry_internal_t* entry) {
 if (!entry->pub.obj || ((uint32_t)entry->pub.block & 0x00000FFF) ||
     entry->pin_count < 0 ||
     (entry->initialized != 0 && entry->initialized != 1) ||
     (entry->flushing != 0 && entry->flushing != 1) ||
     (entry->flushed != 0 && entry->flushed != 1)) {
   return 0;
 } else {
   return 1;
 }
}

// Flush the given cache entry to disk.
static void flush_cache_entry(bc_entry_internal_t* entry) {
  KASSERT_DBG(!entry->flushing);
  KASSERT_DBG(!entry->flushed);
  KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));

  entry->flushing = 1;
  while (!entry->flushed) {
    entry->flushed = 1;
    // Write the data back to disk.  This may block.
    KASSERT(BLOCK_CACHE_BLOCK_SIZE == PAGE_SIZE);
    KASSERT_DBG(entry_is_sane(entry));
    const int result =
        entry->pub.obj->ops->write_page(
            entry->pub.obj, entry->pub.offset, entry->pub.block);
    KASSERT_DBG(entry_is_sane(entry));
    KASSERT_MSG(result == 0, "write_page failed: %s", errorname(-result));

    // Another thread may have dirtied the block during the write, so if flushed
    // == 0 we need to try again.
    KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
  }
  entry->flushing = 0;
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
      bc_entry_internal_t* entry = cache_entry_pop(&g_flush_queue, flushq);
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
static void free_cache_entry(bc_entry_internal_t* entry) {
  KASSERT_DBG(list_link_on_list(&g_flush_queue, &entry->flushq) == 0);
  KASSERT_DBG(list_link_on_list(&g_lru_queue, &entry->lruq) == 0);
  KASSERT_DBG(entry->pin_count == 0);
  KASSERT_DBG(entry->flushed);
  KASSERT_DBG(!entry->flushing);

  //klogf("<block cache free block %d>\n", entry->pub.offset);
  g_size--;
  const uint32_t h = obj_hash(entry->pub.obj, entry->pub.offset);
  KASSERT(htbl_remove(&g_table, h) == 0);

  entry->pub.obj->ops->unref(entry->pub.obj);
  entry->pub.obj = 0x0;

  put_free_block(entry->pub.block);
  kfree(entry);
}

// Go through the cache and look for unpinned entries we can free.  Attempt to
// free up to max_entries of them.
static void maybe_free_cache_space(int max_entries) {
  bc_entry_internal_t* entry = cache_entry_head(g_lru_queue, lruq);
  int entries_freed = 0;
  while (entry && entries_freed < max_entries) {
    KASSERT(entry->pin_count == 0);
    bc_entry_internal_t* next = cache_entry_next(entry, lruq);
    if (entry->flushed && !entry->flushing) {
      KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
      list_remove(&g_lru_queue, &entry->lruq);

      // No-one else has it, so free it.
      free_cache_entry(entry);
      entries_freed++;
    }
    entry = next;
  }

  // If nothing is already flushed, find an unpinned entry and force flush it.
  entry = cache_entry_head(g_lru_queue, lruq);
  while (entry && entries_freed < max_entries) {
    KASSERT(entry->pin_count == 0);
    bc_entry_internal_t* next_entry = cache_entry_next(entry, lruq);
    if (list_link_on_list(&g_flush_queue, &entry->flushq)) {
      list_remove(&g_flush_queue, &entry->flushq);
      list_remove(&g_lru_queue, &entry->lruq);

      flush_cache_entry(entry);

      // flush_cache_entry blocks, so we have to verify that no one took it in
      // the meantime.
      if (entry->flushed && !entry->flushing && entry->pin_count == 0) {
        if (list_link_on_list(&g_lru_queue, &entry->lruq)) {
          list_remove(&g_lru_queue, &entry->lruq);
        }

        KASSERT_DBG(!entry->flushing);
        KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
        // No-one else has it, so free it.
        free_cache_entry(entry);
        entries_freed++;
      }
    }
    entry = next_entry;
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

// Given an existing table entry, wait for it to be initialized (if applicable)
// and add a pin.
static void block_cache_get_internal(bc_entry_internal_t* entry) {
  entry->pin_count++;
  if (!entry->initialized) {
    scheduler_wait_on(&entry->wait_queue);
  }
  KASSERT(entry->initialized);
  if (list_link_on_list(&g_lru_queue, &entry->lruq)) {
    KASSERT(entry->pin_count == 1);
    list_remove(&g_lru_queue, &entry->lruq);
    KASSERT(entry->lruq.next == 0x0);
    KASSERT(entry->lruq.prev == 0x0);
    entry->flushed = 1;
  }
}

int block_cache_get(memobj_t* obj, int offset, bc_entry_t** entry_out) {
  if (!g_initialized) {
    init_block_cache();
  }

  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    if (g_size >= g_max_size) {
      maybe_free_cache_space(g_size - g_max_size + 1);
      if (g_size >= g_max_size) {
        return -ENOMEM;
      }
    }

    // Get a new free block, fill it, and return it.
    void* block = get_free_block();
    if (!block) {
      return -ENOMEM;
    }

    g_size++;
    bc_entry_internal_t* entry = (bc_entry_internal_t*)kmalloc(sizeof(bc_entry_internal_t));
    entry->pub.obj = obj;
    entry->pub.offset = offset;
    entry->pub.block = block;
    entry->pub.block_phys = virt2phys((addr_t)block);
    entry->pin_count = 1;
    entry->initialized = 0;
    entry->flushed = 1;
    entry->flushing = 0;
    entry->flushq = LIST_LINK_INIT;
    entry->lruq = LIST_LINK_INIT;
    kthread_queue_init(&entry->wait_queue);

    // N.B.(aoates): this means that we'll potentially keep the obj (and
    // underlying objects like vnodes) around indefinitely after we're done with
    // them, as long as the bc entries haven't been forced out of the cache.
    obj->ops->ref(obj);

    // Put the uninitialized entry into the table.
    htbl_put(&g_table, h, entry);

    // Read data from the block device into the cache.
    // Note: this may block.
    KASSERT(BLOCK_CACHE_BLOCK_SIZE == PAGE_SIZE);
    const int result =
        obj->ops->read_page(obj, offset, entry->pub.block);
    KASSERT_MSG(result == 0, "read_page failed: %s", errorname(-result));

    entry->initialized = 1;
    scheduler_wake_all(&entry->wait_queue);

    *entry_out = &entry->pub;
    return 0;
  } else {
    bc_entry_internal_t* entry = (bc_entry_internal_t*)tbl_value;
    block_cache_get_internal(entry);
    *entry_out = &entry->pub;
    return 0;
  }
}

int block_cache_lookup(struct memobj* obj, int offset, bc_entry_t** entry_out) {
  if (!g_initialized) {
    init_block_cache();
  }

  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    *entry_out = 0x0;
  } else {
    bc_entry_internal_t* entry = (bc_entry_internal_t*)tbl_value;
    block_cache_get_internal(entry);
    *entry_out = &entry->pub;
  }
  return 0;
}

int block_cache_put(bc_entry_t* entry_pub, block_cache_flush_t flush_mode) {
  KASSERT(g_initialized);

  bc_entry_internal_t* entry = container_of(entry_pub, bc_entry_internal_t, pub);
  KASSERT(entry->pin_count > 0);

  // The block needs to be flushed, if it's not already scheduled for one.
  if (flush_mode != BC_FLUSH_NONE) {
    entry->flushed = 0;
    if (flush_mode == BC_FLUSH_SYNC) {
      if (entry->flushing) {
        scheduler_wait_on(&entry->wait_queue);
      } else {
        if (list_link_on_list(&g_flush_queue, &entry->flushq)) {
          list_remove(&g_flush_queue, &entry->flushq);
        }
        flush_cache_entry(entry);
      }
    } else if (flush_mode == BC_FLUSH_ASYNC) {
      // Only schedule a flush if we're not currently flushing, and don't
      // already have one scheduled.
      if (!entry->flushing &&
          !list_link_on_list(&g_flush_queue, &entry->flushq)) {
        // If the entry is currently flushing, this will schedule it for
        // another, later flush.
        list_push(&g_flush_queue, &entry->flushq);
      }
    }
  }

  KASSERT(!list_link_on_list(&g_lru_queue, &entry->lruq));
  entry->pin_count--;
  if (entry->pin_count == 0) {
    list_push(&g_lru_queue, &entry->lruq);
  }

  return 0;
}

int block_cache_get_pin_count(memobj_t* obj, int offset) {
  if (!g_initialized) {
    return 0;
  }

  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    return 0;
  }

  return ((bc_entry_internal_t*)tbl_value)->pin_count;
}

void block_cache_set_size(int blocks) {
  g_max_size = blocks;
}

int block_cache_get_size() {
  return g_max_size;
}

void block_cache_clear_unpinned() {
  // Flush everything on the flush queue.
  bc_entry_internal_t* entry = cache_entry_pop(&g_flush_queue, flushq);
  while (entry) {
    flush_cache_entry(entry);
    entry = cache_entry_pop(&g_flush_queue, flushq);
  }

  // Clear the LRU queue.
  entry = cache_entry_pop(&g_lru_queue, lruq);
  while (entry) {
    if (!entry->flushed) {
      KASSERT_DBG(entry->flushing);
      scheduler_wait_on(&entry->wait_queue);
    }
    KASSERT_DBG(entry->pin_count == 0);
    KASSERT_DBG(entry->flushed);
    KASSERT_DBG(!entry->flushing);
    KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
    free_cache_entry(entry);
    entry = cache_entry_pop(&g_lru_queue, lruq);
  }
  KASSERT(list_empty(&g_flush_queue));
  KASSERT(list_empty(&g_lru_queue));
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
  bc_entry_internal_t* entry = (bc_entry_internal_t*)value;
  stats->total++;
  if (list_link_on_list(&g_flush_queue, &entry->flushq))
    stats->flushq++;
  else if (entry->pin_count == 0 && entry->flushed == 0)
    stats->flushing++;
  if (entry->flushed)
    stats->flushed++;
  if (list_link_on_list(&g_lru_queue, &entry->lruq))
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
