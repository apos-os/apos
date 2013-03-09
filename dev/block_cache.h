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
#ifndef APOO_DEV_BLOCK_CACHE_H
#define APOO_DEV_BLOCK_CACHE_H

#include "dev/dev.h"
#include "memory.h"

// TODO(aoates): support other block sizes.
#define BLOCK_CACHE_BLOCK_SIZE PAGE_SIZE

// Flush modes for block_cache_put().
typedef enum {
  BC_FLUSH_NONE = 1,
  BC_FLUSH_SYNC,
  BC_FLUSH_ASYNC,
} block_cache_flush_t;

// Return a pointer to the block cache for the given block.  If no entry exists,
// the data is read from the block device into a fresh (or reused) buffer.
//
// offset is the block number to retrieve.
//
// This puts a pin on the returned cache entry.  You MUST call block_cache_put()
// when you are done with the block.
//
// Returns NULL if the block cannot be retrieved, or the cache is full.
void* block_cache_get(dev_t dev, int offset);

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
void block_cache_put(dev_t dev, int offset, block_cache_flush_t flush_mode);

// Returns the current pin count of the given block, or 0 if it is not in the
// cache.
int block_cache_get_pin_count(dev_t dev, int offset);

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
