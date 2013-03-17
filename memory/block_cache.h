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

#include "memory/memory.h"
#include "memory/memobj.h"

// TODO(aoates): support other block sizes.
#define BLOCK_CACHE_BLOCK_SIZE PAGE_SIZE

// Flush modes for block_cache_put().
typedef enum {
  BC_FLUSH_NONE = 1,
  BC_FLUSH_SYNC,
  BC_FLUSH_ASYNC,
} block_cache_flush_t;

// Block cache entry.  Must not be modified outside of the block cache.
typedef struct bc_entry {
  memobj_t* obj;
  uint32_t offset;
  void* block;
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
int block_cache_get(memobj_t* obj, int offset, bc_entry_t** entry_out);

// Legacy/convenience version that returns the bc_entry_t::block directly.
// Returns NULL if the block cannot be retrieved, or the cache is full.
// TODO(aoates): update callers and remove this.
void* block_cache_get_block(memobj_t* obj, int offset);

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
// bc_entry_t after this call unless it has another pin.
int block_cache_put(bc_entry_t* entry, block_cache_flush_t flush_mode);

// Legacy/convenience version that looks up the bc_entry_t again.
// TODO(aoates): update callers and remove this.
void block_cache_put_block(memobj_t* obj, int offset,
                           block_cache_flush_t flush_mode);

// Returns the current pin count of the given block, or 0 if it is not in the
// cache.
int block_cache_get_pin_count(memobj_t* obj, int offset);

// Set the maximum size of the block cache, in blocks.  If the cache is
// currently larger than this, it may not be immediately pruned.
void block_cache_set_size(int blocks);

// Clear the block cache of all unpinned entries, flushing all unflushed entries
// to disk.  Behavior is undefined if any other block cache methods are called
// simultaneously, and is therefore probably only useful for tests.
void block_cache_clear_unpinned();

void block_cache_log_stats();

// TODO(aoates): support sync operations on pinned cache entries.

#endif
