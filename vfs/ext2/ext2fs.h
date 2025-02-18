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

#ifndef APOO_VFS_EXT2_EXT2FS_H
#define APOO_VFS_EXT2_EXT2FS_H

#include "memory/block_cache.h"
#include "memory/memobj.h"
#include "proc/kthread.h"
#include "user/include/apos/dev.h"
#include "vfs/fs.h"

#include "vfs/ext2/ext2-internal.h"

// An ext2 fs structure.
typedef struct {
  fs_t fs;  // Embedded fs interface.

  memobj_t* obj;
  int mounted;
  int read_only;

  // Set to 1 if any part of the ext2 implementation detects an inconsistency in
  // the filesystem.
  int unhealthy;

  // In-memory copy of the superblock.  Only valid if mounted == true.
  ext2_superblock_t sb;

  // How many block groups there are, and the corresponding descriptors.
  unsigned int num_block_groups;
  ext2_block_group_desc_t* block_groups;

  // Lock that protects the mutable portions of the global data structures (sb
  // and block_groups).
  kmutex_t mu;
} ext2fs_t;

// Returns the block size in bytes.
static inline uint32_t ext2_block_size(const ext2fs_t* fs) {
  return 1024 << fs->sb.s_log_block_size;
}

// Get and put the requested block from the fs's device.  If the fs's block size
// is smaller than the block cache's, then the returned pointer may point to the
// middle of a block cache entry.
// TODO(aoates): change these to return the actual bc_entry_t.
int ext2_block_get(const ext2fs_t* fs, int offset, void** out);
void ext2_block_put(const ext2fs_t* fs, int offset, block_cache_flush_t flush_mode);

// Read the superblock and block groups from disk into the given ext2fs_t.
// Returns 0 on success, or -errno if there was an error, or if the on-disk
// filesystem is incompatible with this implementation (for example, by
// requiring unsupported features).
int ext2_read_superblock(ext2fs_t* fs);
int ext2_read_block_groups(ext2fs_t* fs);

// Write the metadata from the superblock or the given block group from the
// ext2fs_t back to disk.
int ext2_flush_superblock(const ext2fs_t* fs);
int ext2_flush_block_group(const ext2fs_t* fs, unsigned int bg);

// Lock and unlock a const ext2fs_t* (which must not point to a const object).
void ext2fs_lock(const ext2fs_t* fs) ACQUIRE(fs->mu);
void ext2fs_unlock(const ext2fs_t* fs) RELEASE(fs->mu);

#endif
