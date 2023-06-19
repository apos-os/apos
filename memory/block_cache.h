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

// A block cache for filesystem blocks.
#ifndef APOO_MEMORY_BLOCK_CACHE_H
#define APOO_MEMORY_BLOCK_CACHE_H

#include <stddef.h>

#include "common/types.h"
#include "memory/memory.h"

// TODO(aoates): support other block sizes.
#define BLOCK_CACHE_BLOCK_SIZE PAGE_SIZE

struct memobj;

// Flush modes for block_cache_put().
typedef enum {
  BC_FLUSH_NONE = 1,
  BC_FLUSH_SYNC,
  BC_FLUSH_ASYNC,
} block_cache_flush_t;

// Block cache entry.  Must not be modified outside of the block cache.
typedef struct bc_entry {
  struct memobj* obj;
  size_t offset;
  void* block;

  // Physical address of the memory block.  Will be block-size-aligned.
  phys_addr_t block_phys;
} bc_entry_t;

// Return a pointer to the block cache for the given block.  If no entry exists,
// the data is read from the memory object into a fresh (or reused) buffer.
//
// offset is the block number to retrieve.
//
// This puts a pin on the returned cache entry.  You MUST call block_cache_put()
// when you are done with the block.
//
// Returns 0 on success, or -errno on error.
int block_cache_get(struct memobj* obj, int offset, bc_entry_t** entry_out);

// Like block_cache_get, but sets *entry_out to NULL if the page isn't resident.
// May still block!
int block_cache_lookup(struct memobj* obj, int offset, bc_entry_t** entry_out);

// Unpin the given cached block.  It may later be reclaimed if memory is needed.
//
// The block's contents may be written back to the underlying disk, depending on
// FLUSH_MODE:
//  * BC_FLUSH_NONE --- the block MAY not be flushed (another thread may cause a
//    flush of the current data, however).  Use if the current thread didn't
//    modify the contents of the block.
//  * BC_FLUSH_SYNC --- the block will be synchronously flushed to disk.
//  * BC_FLUSH_ASYNC --- the block will be asynchronously flushed to disk some
//    time in the future, possibly several seconds away.
//
// Most callers should probably use BC_FLUSH_ASYNC.
//
// Returns 0 on success, or -errno on error.  The caller must not use the
// bc_entry_t after this call unless it has another pin.  On failure the caller
// retains a pin in the entry (and must put it again, e.g. forgoing a flush).
int block_cache_put(bc_entry_t* entry, block_cache_flush_t flush_mode);

// Attempt to migrate the given entry to a different memobj, at the same offset.
// If the entry has multiple references, fails with -EBUSY.  If the target
// memobj already has an entry for that offset, the given entry is simply
// discarded (it does not replace the existing entry), WITHOUT flushing.
//
// Returns the target entry (possibly newly created, possibly existing) in
// target_entry_out, with a new pin on it ("migrating" the pin from the source
// entry, even if the data was discarded).
//
// The caller must externally ensure no other threads attempt to get the source
// entry during this call.
//
// Returns 0 on success.  On success, the given bc_entry_t is no longer valid
// and must not be referenced.
int block_cache_migrate(bc_entry_t* entry_pub, struct memobj* target,
                        bc_entry_t** target_out_out);

// Increment the pin count of the given entry (which is definitionally already
// pinned at least once).  May block.
void block_cache_add_pin(bc_entry_t* entry);

// Attempt to force-flush and free all pages associated with the given memobj.
// If any block cache entries for the memobj are currently pinned, returns
// -EBUSY.  Returns 0 on success.
int block_cache_free_all(struct memobj* obj);

// Returns the current pin count of the given block, or 0 if it is not in the
// cache.
int block_cache_get_pin_count(struct memobj* obj, int offset);

// Set the maximum size of the block cache, in blocks.  If the cache is
// currently larger than this, it may not be immediately pruned.
void block_cache_set_size(int blocks);
int block_cache_get_size(void);

// Get current number of entries in the block cache.
int block_cache_get_num_entries(void);

// Clear the block cache of all unpinned entries, flushing all unflushed entries
// to disk.  Behavior is undefined if any other block cache methods are called
// simultaneously, and is therefore probably only useful for tests.
void block_cache_clear_unpinned(void);

void block_cache_log_stats(void);

// Sets the period of the background flush thread.  Returns the old value.
int block_cache_set_bg_flush_period(int period_ms);

// Wake up the background flush thread to trigger flushes (asyncronously).  If
// the flush thread is currently running, has no effect (i.e. this will not
// necessarily force flushing).
void block_cache_wakeup_flush_thread(void);

// TODO(aoates): support sync operations on pinned cache entries.

#endif
