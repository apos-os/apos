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

#include <stdbool.h>
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

#define KLOG(...) klogfm(KL_BLOCK_CACHE, __VA_ARGS__)

static kmutex_t g_mu;  // Protects all global state.

static int g_size GUARDED_BY(g_mu) = 0;
static int g_max_size GUARDED_BY(g_mu) = DEFAULT_CACHE_SIZE;
// TODO(aoates): make this an atomic.
static int g_flush_queue_period_ms GUARDED_BY(g_mu) = 5000;
// A dummy thread queue that the flush thread waits on, allowing it to be woken
// up (e.g. by tests changing the flush interval).
static kthread_queue_t g_flush_queue_wakeup_queue;

static htbl_t g_table GUARDED_BY(g_mu);

// A cache entry.
typedef struct bc_entry_internal {
  bc_entry_t pub;
  int pin_count;

  // Link on the flush queue and LRU queue.
  list_link_t flushq;
  list_link_t lruq;
  list_link_t memobj_link;

  // Set to true when the entry is flushed to disk, and to false when the entry
  // is taken by a thread.
  bool flushed;
  bool flushing;

  bool initialized;
  int error;                   // Set if failed to be initialized.
  kthread_queue_t wait_queue;  // Threads waiting for init or flush.
} bc_entry_internal_t;

// TODO(aoates): make this flexible.
#define FREE_BLOCK_STACK_SIZE DEFAULT_CACHE_SIZE
static addr_t g_free_block_stack[FREE_BLOCK_STACK_SIZE];
static int g_free_block_stack_idx = 0;  // First free entry.

// Queue of cache entries that need to be flushed.
static list_t g_flush_queue = LIST_INIT_STATIC;

// LRU queue of cache entries that *might* be freeable.
static list_t g_lru_queue = LIST_INIT_STATIC;

// List of entries that have been cleaned up (removed from the table) but still
// need to have their memory freed and underlying memobjs unref'd.
static list_t g_cleanup_list = LIST_INIT_STATIC;

#define cache_entry_pop(list, link_name) \
    container_of(list_pop(list), bc_entry_internal_t, link_name)

#define cache_entry_next(entry, link_name) \
    container_of((entry)->link_name.next, bc_entry_internal_t, link_name)

#define cache_entry_head(list, link_name) \
    container_of((list).head, bc_entry_internal_t, link_name)

// Acquire more free blocks and add them to the free block stack.
static void get_more_free_blocks(void) {
  kmutex_assert_is_held(&g_mu);
  KASSERT(FREE_BLOCK_STACK_SIZE - g_free_block_stack_idx > BLOCKS_PER_PAGE);
  const phys_addr_t phys_page = page_frame_alloc();
  if (phys_page == 0x0) {
    return;
  }
  const addr_t page = phys2virt(phys_page);

  KASSERT(PAGE_SIZE % BLOCK_CACHE_BLOCK_SIZE == 0);
  for (int i = 0; i < BLOCKS_PER_PAGE; ++i) {
    g_free_block_stack[g_free_block_stack_idx++] =
        page + BLOCK_CACHE_BLOCK_SIZE * i;
  }
}

// Return a free block for a new cache entry.
static void* get_free_block(void) {
  kmutex_assert_is_held(&g_mu);
  if (g_free_block_stack_idx == 0) {
    get_more_free_blocks();
  }

  // If we can't get any new blocks, we must be done.
  if (g_free_block_stack_idx == 0) {
    return 0x0;
  }
  const addr_t block = g_free_block_stack[--g_free_block_stack_idx];
  return (void*)block;
}

// Return a free block to the stack.
static void put_free_block(void* block) {
  KASSERT_DBG(block != NULL);
  kmutex_assert_is_held(&g_mu);
  if (g_free_block_stack_idx == FREE_BLOCK_STACK_SIZE) {
    KLOG(WARNING, "dropping free block because the free block cache "
         "is full!\n");
    // TODO(aoates): try to compact free block stack and free pages, and/or
    // resize the stack to fit.
    return;
  }
  if (ENABLE_KERNEL_SAFETY_NETS) {
    kmemset(block, 0xB, BLOCK_CACHE_BLOCK_SIZE);
  }
  g_free_block_stack[g_free_block_stack_idx++] = (addr_t)block;
}

static uint32_t obj_hash(memobj_t* obj, int offset) {
  uint32_t array[3] = {obj->type, obj->id, offset};
  uint32_t h = fnv_hash_array(array, 3 * sizeof(uint32_t));
  return h;
}

// Basic sanity checks on a bc_entry_t.
static int entry_is_sane(bc_entry_internal_t* entry) {
 if (!entry->pub.obj || ((addr_t)entry->pub.block & PAGE_OFFSET_MASK) ||
     entry->pin_count < 0) {
   return 0;
 } else {
   return 1;
 }
}

// Flush the given cache entry to disk.
// May block and release the state mutex.  Callers must ensure block cache state
// is consistent across this call.
static void flush_cache_entry(bc_entry_internal_t* entry) {
  kmutex_assert_is_held(&g_mu);
  KASSERT_DBG(!entry->flushing);
  KASSERT_DBG(!entry->flushed);
  KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));

  entry->flushing = true;
  while (!entry->flushed) {
    entry->flushed = true;
    // Write the data back to disk.  This may block.
    KASSERT(BLOCK_CACHE_BLOCK_SIZE == PAGE_SIZE);
    KASSERT_DBG(entry_is_sane(entry));
    kmutex_unlock(&g_mu);
    const int result =
        entry->pub.obj->ops->write_page(
            entry->pub.obj, entry->pub.offset, entry->pub.block);
    kmutex_lock(&g_mu);
    KASSERT_DBG(entry_is_sane(entry));
    // TODO(aoates): propagate the error back to any synchronous waiters.
    if (result != 0) {
      KLOG(
          WARNING,
          "block cache: write_page(object=%p (id %u), offset=%zu) failed: %s\n",
          entry->pub.obj, entry->pub.obj->id, entry->pub.offset,
          errorname(-result));
      if (result == -ETIMEDOUT) {
        entry->flushed = false;
      }
    }

    // Another thread may have dirtied the block during the write, so if flushed
    // == 0 we need to try again.
    KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
  }
  entry->flushing = false;
  scheduler_wake_all(&entry->wait_queue);
}

// As above, but if the entry is currently already being flushed by another
// thread, waits for that flush to finish.
// Note: if the entry isn't pinned, it could be deleted by the time this
// returns! (if another thread is flushing it, then deletes it before we wake up
// after blocking on the flush).
static int flush_or_wait(bc_entry_internal_t* entry) {
  kmutex_assert_is_held(&g_mu);
  if (entry->flushing) {
    int result = scheduler_wait_on_locked(&entry->wait_queue, -1, &g_mu);
    // entry may be dead!  Set to NULL defensively.
    entry = NULL;
    KASSERT_DBG(result != SWAIT_TIMEOUT);
    if (result == SWAIT_INTERRUPTED) {
      return -EINTR;
    }
  } else {
    if (list_link_on_list(&g_flush_queue, &entry->flushq)) {
      list_remove(&g_flush_queue, &entry->flushq);
    }
    flush_cache_entry(entry);
  }
  return 0;
}

// The flush thread that works through the flush queue, flushing cache entries
// and sleeping.
static kthread_t g_flush_queue_thread;
static void* flush_queue_thread(void* arg) {
  sched_enable_preemption_for_test();
  const int kMaxFlushesPerCycle = 1000;
  kmutex_lock(&g_mu);
  while (1) {
    int result = scheduler_wait_on_locked(&g_flush_queue_wakeup_queue,
                                          g_flush_queue_period_ms, &g_mu);
    KASSERT(result != SWAIT_INTERRUPTED);
    int flushed = 0;
    while (flushed < kMaxFlushesPerCycle) {
      bc_entry_internal_t* entry = cache_entry_pop(&g_flush_queue, flushq);
      if (!entry) break;
      // NOTE: this will unlock and relock g_mu.
      flush_cache_entry(entry);
      flushed++;
    }
    if (flushed > 0)
      KLOG(DEBUG, "<block cache flushed %d entries>\n", flushed);
  }
  die("unreachable");
  return 0x0;
}

// Remove the given (flushed and unpinned) cache entry from the table, release
// its block, and queue it to be freed later.
// TODO(aoates): reexamine this two-stage deletion process after the
// memobj/block cache/bc_entry_t relationship is reexamined to solve the bug
// with abandoned shadow entries.
static void cleanup_cache_entry(bc_entry_internal_t* entry) {
  kmutex_assert_is_held(&g_mu);
  KASSERT_DBG(list_link_on_list(&g_flush_queue, &entry->flushq) == 0);
  KASSERT_DBG(list_link_on_list(&g_lru_queue, &entry->lruq) == 0);
  KASSERT_DBG(entry->pin_count == 0);
  KASSERT_DBG(entry->flushed);
  KASSERT_DBG(!entry->flushing);

  KASSERT_DBG(g_size > 0);
  g_size--;
  // If uninitialized, it was not successfully populated and was already removed
  // from the hashtable.
  if (entry->initialized) {
    KASSERT_DBG(entry->error == 0);
    KLOG(DEBUG2, "<block cache free block %zu>\n", entry->pub.offset);
    const uint32_t h = obj_hash(entry->pub.obj, entry->pub.offset);
    KASSERT(htbl_remove(&g_table, h) == 0);
    entry->initialized = false;
  }
  if (entry->pub.block) {
    put_free_block(entry->pub.block);
  }

  if (ENABLE_KERNEL_SAFETY_NETS) {
    entry->pub.block = NULL;
    entry->pub.block_phys = 0;
    entry->pub.offset = (size_t)-1;
  }
  list_push(&g_cleanup_list, &entry->lruq);
}

static void unpin_entry(bc_entry_internal_t** entry_ptr) {
  bc_entry_internal_t* entry = *entry_ptr;
  KASSERT_DBG(entry->pin_count >= 0);
  kmutex_assert_is_held(&g_mu);
  entry->pin_count--;
  if (entry->pin_count == 0) {
    if (entry->error == 0) {  // Typical case.
      list_push(&g_lru_queue, &entry->lruq);
    } else {
      cleanup_cache_entry(entry);
    }
  }
  *entry_ptr = NULL;
}

// Free any entries queued for cleanup and unref the underlying memobjs.
// May block and release/acquire the state mutex.
static void free_dead_entries(void) {
  kmutex_assert_is_held(&g_mu);
  while (!list_empty(&g_cleanup_list)) {
    bc_entry_internal_t* entry = cache_entry_pop(&g_cleanup_list, lruq);

    KASSERT_DBG(entry->initialized == false);
    KASSERT_DBG(entry->pin_count == 0);
    list_remove(&entry->pub.obj->bc_entries, &entry->memobj_link);
    entry->pub.obj->num_bc_entries--;
    KASSERT_DBG(entry->pub.obj->num_bc_entries >= 0);
    kmutex_unlock(&g_mu);

    entry->pub.obj->ops->unref(entry->pub.obj);  // May block.
    entry->pub.obj = 0x0;
    kfree(entry);

    kmutex_lock(&g_mu);
  }
}

// Go through the cache and look for unpinned entries we can free.  Attempt to
// free up to max_entries of them.
static void maybe_free_cache_space(int max_entries) {
  kmutex_assert_is_held(&g_mu);
  bc_entry_internal_t* entry = cache_entry_head(g_lru_queue, lruq);
  int entries_freed = 0;
  while (entry && entries_freed < max_entries) {
    KASSERT(entry->pin_count == 0);
    bc_entry_internal_t* next = cache_entry_next(entry, lruq);
    if (entry->flushed && !entry->flushing) {
      KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
      list_remove(&g_lru_queue, &entry->lruq);

      // No-one else has it, so free it.
      cleanup_cache_entry(entry);
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
        cleanup_cache_entry(entry);
        entries_freed++;
      }
    }
    entry = next_entry;
  }
  KLOG(DEBUG2, "block cache freed %d entries\n", entries_freed);

  // Actually free the entries and unref memobjs associated with any blocks we
  // just freed.  May block.
  free_dead_entries();

  // TODO(aoates): if something is currently flushing, block for it to finish.
}

void block_cache_init(void) {
  kmutex_init(&g_mu);
  kmutex_constructor(&g_mu);
  htbl_init(&g_table, g_max_size * 2);
  kthread_queue_init(&g_flush_queue_wakeup_queue);
  KASSERT(kthread_create(&g_flush_queue_thread, &flush_queue_thread, 0x0) == 0);
  scheduler_make_runnable(g_flush_queue_thread);
}

// Given an existing table entry, wait for it to be initialized (if applicable)
// and add a pin.  Succeeds (returns 0) unless interrupted.
static int block_cache_get_existing(bc_entry_internal_t* entry) {
  kmutex_assert_is_held(&g_mu);
  entry->pin_count++;
  if (!entry->initialized) {
    int result = scheduler_wait_on_locked(&entry->wait_queue, -1, &g_mu);
    KASSERT_DBG(result != SWAIT_TIMEOUT);
    if (result == SWAIT_INTERRUPTED) {
      unpin_entry(&entry);
      return -EINTR;
    }
  }

  if (!entry->initialized) {
    KASSERT_DBG(entry->error != 0);
    int result = entry->error;
    unpin_entry(&entry);
    return result;
  }

  KASSERT_DBG(entry->error == 0);
  if (list_link_on_list(&g_lru_queue, &entry->lruq)) {
    KASSERT(entry->pin_count == 1);
    list_remove(&g_lru_queue, &entry->lruq);
    KASSERT(entry->lruq.next == 0x0);
    KASSERT(entry->lruq.prev == 0x0);
  }
  return 0;
}

// Get or create a new entry.  If a block is supplied, and a new entry is
// created, then that block is used unchanged.  Otherwise, a new block is
// created and read from the object.
static int block_cache_get_internal(memobj_t* obj, int offset,
                                    bc_entry_t** entry_out,
                                    void* existing_block) REQUIRES(g_mu) {
  kmutex_assert_is_held(&g_mu);
  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  int result;
  if (!tbl_value && htbl_get(&g_table, h, &tbl_value) != 0) {
    void* block = existing_block;
    if (!block) {
      block = get_free_block();
      if (!block) {
        return -ENOMEM;
      }
    }

    g_size++;
    bc_entry_internal_t* entry = (bc_entry_internal_t*)kmalloc(sizeof(bc_entry_internal_t));
    entry->pub.obj = obj;
    entry->pub.offset = offset;
    entry->pub.block = block;
    entry->pub.block_phys = virt2phys((addr_t)block);
    entry->pin_count = 1;
    entry->initialized = false;
    entry->error = 0;
    entry->flushed = true;
    entry->flushing = false;
    entry->flushq = LIST_LINK_INIT;
    entry->lruq = LIST_LINK_INIT;
    entry->memobj_link = LIST_LINK_INIT;
    kthread_queue_init(&entry->wait_queue);

    // Put the uninitialized entry into the table.
    htbl_put(&g_table, h, entry);
    KASSERT_DBG(obj->num_bc_entries >= 0);
    list_push(&obj->bc_entries, &entry->memobj_link);
    obj->num_bc_entries++;

    // Unlock mutex around reentrant and blocking operations.
    kmutex_unlock(&g_mu);

    // N.B.(aoates): this means that we'll potentially keep the obj (and
    // underlying objects like vnodes) around indefinitely after we're done with
    // them, as long as the bc entries haven't been forced out of the cache.
    // Safe to call without lock because it doesn't touch our state (unless
    // calls back into block cache) and we already hold a ref to the memobj in
    // `obj`, so it will stay live.
    obj->ops->ref(obj);

    result = 0;
    if (!existing_block) {
      // Read data from the block device into the cache.
      // Note: this may block.
      KASSERT(BLOCK_CACHE_BLOCK_SIZE == PAGE_SIZE);
      result = obj->ops->read_page(obj, offset, entry->pub.block);
    }
    kmutex_lock(&g_mu);

    entry->error = result;
    scheduler_wake_all(&entry->wait_queue);

    if (result) {
      htbl_remove(&g_table, h);
      unpin_entry(&entry);
      *entry_out = NULL;
    } else {
      entry->initialized = true;
      *entry_out = &entry->pub;
    }
  } else {
    bc_entry_internal_t* entry = (bc_entry_internal_t*)tbl_value;
    result = block_cache_get_existing(entry);
    if (result) {
      *entry_out = NULL;
      return result;
    }
    *entry_out = &entry->pub;
  }
  return result;
}

int block_cache_get(memobj_t* obj, int offset, bc_entry_t** entry_out) {
  kmutex_lock(&g_mu);
  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    if (g_size >= g_max_size) {
      maybe_free_cache_space(g_size - g_max_size + 1);
      if (g_size >= g_max_size) {
        kmutex_unlock(&g_mu);
        return -ENOMEM;
      }
    }
  }

  // While freeing cache space above, someone else may have come along and
  // created the entry, so we need to check again.
  int result = block_cache_get_internal(obj, offset, entry_out,
                                        /* existing_block= */ NULL);
  kmutex_unlock(&g_mu);
  return result;
}

int block_cache_lookup(struct memobj* obj, int offset, bc_entry_t** entry_out) {
  kmutex_lock(&g_mu);
  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    *entry_out = 0x0;
  } else {
    bc_entry_internal_t* entry = (bc_entry_internal_t*)tbl_value;
    int result = block_cache_get_existing(entry);
    if (result) {
      kmutex_unlock(&g_mu);
      *entry_out = NULL;
      return result;
    }
    *entry_out = &entry->pub;
  }
  kmutex_unlock(&g_mu);
  return 0;
}

int block_cache_put(bc_entry_t* entry_pub, block_cache_flush_t flush_mode) {
  kmutex_lock(&g_mu);
  bc_entry_internal_t* entry = container_of(entry_pub, bc_entry_internal_t, pub);
  KASSERT(entry->pin_count > 0);
  KASSERT_DBG(entry->initialized);
  KASSERT_DBG(entry->error == 0);

  // The block needs to be flushed, if it's not already scheduled for one.
  if (flush_mode != BC_FLUSH_NONE) {
    entry->flushed = 0;
    if (flush_mode == BC_FLUSH_SYNC) {
      int result = flush_or_wait(entry);
      if (result) {
        kmutex_unlock(&g_mu);
        return result;
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
  unpin_entry(&entry);

  kmutex_unlock(&g_mu);
  return 0;
}

int block_cache_migrate(bc_entry_t* entry_pub, struct memobj* target,
                        bc_entry_t** target_entry_out) {
  KASSERT(entry_pub->obj != target);

  kmutex_lock(&g_mu);
  bc_entry_internal_t* entry = container_of(entry_pub, bc_entry_internal_t, pub);
  KASSERT(entry->pin_count > 0);
  KASSERT_DBG(entry->initialized);
  KASSERT_DBG(entry->error == 0);

  if (entry->pin_count > 1) {
    kmutex_unlock(&g_mu);
    return -EBUSY;
  }

  int result = 0;
  if (entry->flushing || !entry->flushed) {
    result = flush_or_wait(entry);
    if (result) {
      kmutex_unlock(&g_mu);
      return result;
    }
  }

  // Get the appropriate page from the target memobj; supply the existing
  // entry's block to use if the entry needs creation.
  result = block_cache_get_internal(target, entry_pub->offset, target_entry_out,
                                    /* existing_block= */ entry_pub->block);
  if (result) {
    kmutex_unlock(&g_mu);
    return result;
  }
  // These should only trigger if another thread grabbed the entry, violating
  // the contract with the caller.
  KASSERT_DBG(!entry->flushing);
  KASSERT_DBG(entry->flushed);
  KASSERT_DBG(entry->pin_count == 1);
  KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));

  // If we indeed adopted this new block, deal with the old one.
  bc_entry_t* target_entry = *target_entry_out;
  if (target_entry->block == entry_pub->block) {
    entry_pub->block = NULL;
    entry_pub->block_phys = 0;
  }

  // We're now done with the source entry, one way or another.
  entry->pin_count--;
  cleanup_cache_entry(entry);

  kmutex_unlock(&g_mu);
  return 0;
}

void block_cache_add_pin(bc_entry_t* entry_pub) {
  // TODO(aoates): use an atomic for pin_count and make this non-blocking.
  bc_entry_internal_t* entry =
      container_of(entry_pub, bc_entry_internal_t, pub);
  kmutex_lock(&g_mu);
  KASSERT_DBG(entry->pin_count > 0);
  entry->pin_count++;
  kmutex_unlock(&g_mu);
}

int block_cache_free_all(struct memobj* obj) {
  // TODO(aoates): there is a decent amount of shared logic between this,
  // block_cache_clear_unpinned(), put(), and maybe_free_cache_space().  Maybe
  // combine into a helper?
  kmutex_lock(&g_mu);
  while (!list_empty(&obj->bc_entries)) {
    bc_entry_internal_t* entry =
        container_of(obj->bc_entries.head, bc_entry_internal_t, memobj_link);
    if (entry->pin_count) {
      kmutex_unlock(&g_mu);
      return -EBUSY;
    }
    // This block may already be on the cleanup list.
    if (entry->pub.block) {
      if (!entry->flushed || entry->flushing) {
        int result = flush_or_wait(entry);  // May block and change entry.
        if (result) {
          kmutex_unlock(&g_mu);
          return result;
        }
        // We don't know what happened --- `entry` may point to invalid memory
        // now!  Or be pinned, flushing, or dirty.  Just retry from the start.
        continue;
      }

      // Sanity checks.
      KASSERT_DBG(entry->pub.obj == obj);
      KASSERT_DBG(entry->pin_count == 0);
      KASSERT_DBG(entry->flushed);
      KASSERT_DBG(!entry->flushing);
      KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));
      // TODO(aoates): is there any scenario when the entry _won't_ be on the LRU
      // queue here?  If so, write a test for it.
      if (list_link_on_list(&g_lru_queue, &entry->lruq)) {
        list_remove(&g_lru_queue, &entry->lruq);
      }
      cleanup_cache_entry(entry);
    } else {
      KASSERT_DBG(list_link_on_list(&g_cleanup_list, &entry->lruq));
    }

    // TODO(aoates): figure out how to call free_dead_entries() once at the end.
    free_dead_entries();  // May block.
  }
  kmutex_unlock(&g_mu);
  return 0;
}

int block_cache_get_pin_count(memobj_t* obj, int offset) {
  kmutex_lock(&g_mu);
  const uint32_t h = obj_hash(obj, offset);
  void* tbl_value = 0x0;
  if (htbl_get(&g_table, h, &tbl_value) != 0) {
    kmutex_unlock(&g_mu);
    return 0;
  }

  int result = ((bc_entry_internal_t*)tbl_value)->pin_count;
  kmutex_unlock(&g_mu);
  return result;
}

void block_cache_set_size(int blocks) {
  kmutex_lock(&g_mu);
  g_max_size = blocks;
  kmutex_unlock(&g_mu);
}

int block_cache_get_size(void) {
  kmutex_lock(&g_mu);
  int result = g_max_size;
  kmutex_unlock(&g_mu);
  return result;
}

int block_cache_get_num_entries(void) {
  kmutex_lock(&g_mu);
  int result = g_size;
  kmutex_unlock(&g_mu);
  return result;
}

void block_cache_clear_unpinned(void) {
  // Since freeing entries from the LRU queue may cause dirtying of additional
  // entries (e.g. this happens with ext2), keep trying until the flush queue is
  // empty.
  kmutex_lock(&g_mu);
  do {
    // Flush everything on the flush queue.
    bc_entry_internal_t* entry = cache_entry_pop(&g_flush_queue, flushq);
    while (entry) {
      flush_cache_entry(entry);
      entry = cache_entry_pop(&g_flush_queue, flushq);
    }

    // Clear the LRU queue of flushed entries.
    entry = cache_entry_head(g_lru_queue, lruq);
    while (entry) {
      if (entry->flushing) {
        int result = scheduler_wait_on_locked(&entry->wait_queue, -1, &g_mu);
        // N.B.(aoates): this is buggy --- we don't hold a pin on the entry, so
        // it could have been freed while we were sleeping above.
        // TODO(aoates): fix this so it works safely concurretly, like
        // block_cache_free_all() or maybe_free_cache_space().
        KASSERT(result == 0);
      }
      if (!entry->flushed) {
        // Skip it, we'll flush it above and get it the next time around.
        entry = cache_entry_next(entry, lruq);
        continue;
      }
      KASSERT_DBG(entry->pin_count == 0);
      KASSERT_DBG(entry->flushed);
      KASSERT_DBG(!entry->flushing);
      KASSERT_DBG(!list_link_on_list(&g_flush_queue, &entry->flushq));

      bc_entry_internal_t* next_entry = cache_entry_next(entry, lruq);
      list_remove(&g_lru_queue, &entry->lruq);
      cleanup_cache_entry(entry);
      entry = next_entry;
    }
    free_dead_entries();  // May block.
  } while (!list_empty(&g_flush_queue) || !list_empty(&g_lru_queue));
  kmutex_unlock(&g_mu);
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

static void stats_counter_func(void* arg, htbl_key_t key, void* value) {
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
void block_cache_log_stats(void) {
  kmutex_lock(&g_mu);
  stats_t stats;
  kmemset(&stats, 0, sizeof(stats_t));
  htbl_iterate(&g_table, &stats_counter_func, &stats);
  KLOG(INFO, "Block cache stats:\n");
  KLOG(INFO, "  total entries: %d\n", stats.total);
  KLOG(INFO, "         pinned: %d\n", stats.pinned);
  KLOG(INFO, "     total pins: %d\n", stats.total_pins);
  KLOG(INFO, "      on flushq: %d\n", stats.flushq);
  KLOG(INFO, "         on lru: %d\n", stats.lru);
  KLOG(INFO, "        flushed: %d\n", stats.flushed);
  KLOG(INFO, "       flushing: %d\n", stats.flushing);
  kmutex_unlock(&g_mu);
}

int block_cache_set_bg_flush_period(int period_ms) {
  kmutex_lock(&g_mu);
  int old = g_flush_queue_period_ms;
  g_flush_queue_period_ms = period_ms;
  kmutex_unlock(&g_mu);
  block_cache_wakeup_flush_thread();
  return old;
}

void block_cache_wakeup_flush_thread(void) {
  scheduler_wake_all(&g_flush_queue_wakeup_queue);
}

bool block_cache_quiesce_flushing(int max_ms) {
  KASSERT(max_ms > 0);
  apos_ms_t start = get_time_ms();
  while (get_time_ms() <= start + max_ms) {
    kmutex_lock(&g_mu);
    if (list_empty(&g_flush_queue)) {
      kmutex_unlock(&g_mu);
      KLOG(INFO, "block cache: quiesced after %d ms\n", get_time_ms() - start);
      return true;
    }
    kmutex_unlock(&g_mu);
    block_cache_wakeup_flush_thread();
    ksleep(10);
  }
  KLOG(INFO, "block cache: failed to quiesce within %d ms\n", max_ms);
  return false;
}
