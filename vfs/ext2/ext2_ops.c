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

#include "vfs/ext2/ext2_ops.h"

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/block_cache.h"
#include "kmalloc.h"
#include "vfs/vfs.h"

#include "vfs/ext2/ext2-internal.h"
#include "vfs/ext2/ext2fs.h"

static vnode_t* ext2_alloc_vnode(struct fs* fs);
static int ext2_get_root(struct fs* fs);
static int ext2_get_vnode(vnode_t* vnode);
static int ext2_put_vnode(vnode_t* vnode);
static int ext2_lookup(vnode_t* parent, const char* name);
static int ext2_create(vnode_t* parent, const char* name);
static int ext2_mkdir(vnode_t* parent, const char* name);
static int ext2_rmdir(vnode_t* parent, const char* name);
static int ext2_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int ext2_write(vnode_t* vnode, int offset, const void* buf, int bufsize);
static int ext2_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int ext2_unlink(vnode_t* parent, const char* name);
static int ext2_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);

// Given a block-sized bitmap (i.e. a block group's block or inode bitmap),
// return the value of the Nth entry.
static inline int bg_bitmap_get(ext2fs_t* fs, const void* bitmap, int n) {
  KASSERT_DBG(n >= 0);
  return (((uint8_t*)bitmap)[n / 8] >> (n % 8)) & 0x01;
}

// Set the Nth bit in the given block-sized bitmap.
static inline void bg_bitmap_set(void* bitmap, int n) {
  KASSERT_DBG(n >= 0);
  ((uint8_t*)bitmap)[n / 8] |= (0x01 << (n % 8));
}

// Clear the Nth bit in the given block-sized bitmap.
static inline void bg_bitmap_clear(void* bitmap, int n) {
  KASSERT_DBG(n >= 0);
  ((uint8_t*)bitmap)[n / 8] &= ~(0x01 << (n % 8));
}

// Given a block-sized bitmap, return the index of the first unset bit, or -1 if
// all bits are set.
static int bg_bitmap_find_free(ext2fs_t* fs, uint8_t* bitmap) {
  const unsigned int block_size = ext2_block_size(fs);
  unsigned int idx = 0;
  for (idx = 0; idx < block_size; ++idx) {
    if (bitmap[idx] != 0xFF) break;
  }
  if (idx == block_size) {
    return -1;
  }

  const uint8_t value = bitmap[idx];
  int bit_idx;
  for (bit_idx = 0; bit_idx < 8; ++bit_idx) {
    if ((value & (0x01 << bit_idx)) == 0x0) break;
  }
  // We should have found at least *one* free bit!
  KASSERT(bit_idx != 8);
  return idx * 8 + bit_idx;
}

// Return the block group that the given inode is in.
static inline int get_inode_bg(ext2fs_t* fs, uint32_t inode_num) {
  return (inode_num - 1) / fs->sb.s_inodes_per_group;
}
static inline int get_inode_bg_idx(ext2fs_t* fs, uint32_t inode_num) {
  return (inode_num - 1) % fs->sb.s_inodes_per_group;
}

// Return the block group that the given block is in.
static inline int get_block_bg(ext2fs_t* fs, uint32_t block_num) {
  return (block_num - fs->sb.s_first_data_block) / fs->sb.s_blocks_per_group;
}
static inline int get_block_bg_idx(ext2fs_t* fs, uint32_t block_num) {
  return (block_num - fs->sb.s_first_data_block) % fs->sb.s_blocks_per_group;
}

// Helper for get_inode and write_inode.  Given an inode number, return (via out
// parameters) the inode's block group, the index of the inode within that block
// group, the block number of the corresponding inode bitmap, and the block
// number and byte index of the corresponding block in the appropriate block
// group's inode table.
// TODO(aoates): use this for allocate_inode as well.
static void get_inode_info(ext2fs_t* fs, uint32_t inode_num,
                           uint32_t* block_group_out,
                           uint32_t* inode_bg_idx_out,
                           uint32_t* inode_bitmap_block_out,
                           uint32_t* inode_table_block_out,
                           uint32_t* inode_table_offset_out) {
  // Find the block group and load it's inode bitmap.
  const uint32_t bg = get_inode_bg(fs, inode_num);
  const uint32_t bg_inode_idx = get_inode_bg_idx(fs, inode_num);
  KASSERT(bg < fs->num_block_groups);
  *inode_bitmap_block_out = fs->block_groups[bg].bg_inode_bitmap;

  // The inode table map span multiple blocks, so figure out which block we
  // need.
  const uint32_t block_size = ext2_block_size(fs);
  KASSERT(block_size % fs->sb.s_inode_size == 0);
  const uint32_t bg_inode_table_block_offset =
      (bg_inode_idx * fs->sb.s_inode_size) / block_size;
  *inode_table_offset_out =
      (bg_inode_idx * fs->sb.s_inode_size) % block_size;
  *inode_table_block_out =
      fs->block_groups[bg].bg_inode_table + bg_inode_table_block_offset;
  *block_group_out = bg;
  *inode_bg_idx_out = bg_inode_idx;
}

// Given an inode number (1-indexed), find the corresponding inode on disk and
// fill the given ext2_inode_t.  Only reads the first sizeof(ext2_inode_t) ==
// 128 bytes, ignoring anything after that.
//
// Returns 0 on success, or -errno on error.
static int get_inode(ext2fs_t* fs, uint32_t inode_num, ext2_inode_t* inode) {
  if (inode_num <= 0) {
    return -ERANGE;
  }
  if (inode_num > fs->sb.s_inodes_count) {
    return -ENOENT;
  }

  uint32_t block_group = 0;
  uint32_t inode_bg_idx = 0;
  uint32_t inode_bitmap_block = 0;
  uint32_t inode_table_block = 0;
  uint32_t inode_table_offset = 0;
  get_inode_info(fs, inode_num, &block_group, &inode_bg_idx,
                 &inode_bitmap_block, &inode_table_block, &inode_table_offset);

  // Find the block group and load it's inode bitmap.
  void* inode_bitmap = block_cache_get(fs->dev, inode_bitmap_block);
  if (!inode_bitmap) {
    klogf("ext2: warning: couldn't get inode bitmap for block "
          "group %d (block %d)\n", block_group, inode_bitmap_block);
    return -ENOENT;
  }
  if (!bg_bitmap_get(fs, inode_bitmap, inode_bg_idx)) {
    block_cache_put(fs->dev, inode_bitmap_block);
    return -ENOENT;
  }
  block_cache_put(fs->dev, inode_bitmap_block);

  // We know that the inode is allocated, now get it from the inode table.
  void* inode_table = block_cache_get(fs->dev, inode_table_block);
  if (!inode_table) {
    klogf("ext2: warning: couldn't get inode table for block "
          "group %d (block %d)\n", block_group, inode_table_block);
    return -ENOENT;
  }

  // TODO(aoates): we needto check the inode bitmap again!

  ext2_inode_t* disk_inode = (ext2_inode_t*)(
      inode_table + inode_table_offset);
  kmemcpy(inode, disk_inode, sizeof(ext2_inode_t));
  block_cache_put(fs->dev, inode_table_block);

  ext2_inode_ltoh(inode);

  return 0;
}

// Given an inode number and data, copy it back to disk.
static int write_inode(ext2fs_t* fs, uint32_t inode_num,
                       const ext2_inode_t* inode) {
  if (inode_num <= 0) {
    return -ERANGE;
  }
  if (inode_num > fs->sb.s_inodes_count) {
    return -ENOENT;
  }

  uint32_t block_group = 0;
  uint32_t inode_bg_idx = 0;
  uint32_t inode_bitmap_block = 0;
  uint32_t inode_table_block = 0;
  uint32_t inode_table_offset = 0;
  get_inode_info(fs, inode_num, &block_group, &inode_bg_idx,
                 &inode_bitmap_block, &inode_table_block, &inode_table_offset);

  // Get the needed inode table block.
  void* inode_table = block_cache_get(fs->dev, inode_table_block);
  if (!inode_table) {
    klogf("ext2: warning: couldn't get inode table for block "
          "group %d (block %d)\n", block_group, inode_table_block);
    return -ENOENT;
  }

  ext2_inode_t* disk_inode = (ext2_inode_t*)(
      inode_table + inode_table_offset);
  kmemcpy(disk_inode, inode, sizeof(ext2_inode_t));
  ext2_inode_ltoh(disk_inode);

  block_cache_put(fs->dev, inode_table_block);
  return 0;
}

// Given a block number, return the ith uint32_t of that block.
static uint32_t get_block_idx(ext2fs_t* fs, uint32_t block_num, uint32_t idx) {
  void* block = block_cache_get(fs->dev, block_num);
  KASSERT(block);
  uint32_t value = ((uint32_t*)block)[idx];
  block_cache_put(fs->dev, block_num);
  return ltoh32(value);
}

// Given a block number, set the ith uint32_t of that block.
static void set_block_idx(ext2fs_t* fs, uint32_t block_num, uint32_t idx,
                          uint32_t value) {
  void* block = block_cache_get(fs->dev, block_num);
  KASSERT(block);
  ((uint32_t*)block)[idx] = htol32(value);
  block_cache_put(fs->dev, block_num);
}

// Given an inode and a block index within that inode (that's not in the inode's
// i_block list), return the indirect block containing that block's address (in
// *indirect_block_out) and the offset within that block (in
// *indirect_block_offset_out).
//
// Returns 0 on success, or -errno on error.
static int get_inode_indirect_block(ext2fs_t* fs, ext2_inode_t* inode,
                                    uint32_t inode_block,
                                    uint32_t* indirect_block_out,
                                    uint32_t* indirect_block_offset_out) {
  const uint32_t kDirectBlocks = 12;
  const uint32_t kBlocksPerIndirect = ext2_block_size(fs) / sizeof(uint32_t);
  const uint32_t kBlocksPerDoubleIndirect =
      kBlocksPerIndirect * kBlocksPerIndirect;
  const uint32_t kBlocksPerTripleIndirect =
      kBlocksPerDoubleIndirect * kBlocksPerIndirect;

  if (inode_block < kDirectBlocks) {
    return -ERANGE;
  } else if (inode_block < kDirectBlocks + kBlocksPerIndirect) {
    // Single indirect block.
    *indirect_block_out = inode->i_block[12];
    *indirect_block_offset_out = inode_block - kDirectBlocks;
    return 0;
  } else if (inode_block < kDirectBlocks + kBlocksPerIndirect +
             kBlocksPerDoubleIndirect) {
    // Doubly indirect block.
    // The index within the doubly indirect blocks.
    const uint32_t dbl_block_idx =
        inode_block - kDirectBlocks - kBlocksPerIndirect;
    const uint32_t dbl_block = inode->i_block[13];
    const uint32_t indirect_block = get_block_idx(
        fs, dbl_block, dbl_block_idx / kBlocksPerIndirect);

    *indirect_block_out = indirect_block;
    *indirect_block_offset_out = dbl_block_idx % kBlocksPerIndirect;
    return 0;
  } else {
    // Triply indirect block.
    KASSERT(inode_block < kDirectBlocks + kBlocksPerIndirect +
            kBlocksPerDoubleIndirect + kBlocksPerTripleIndirect);
    const uint32_t triple_block_idx =
        inode_block - kDirectBlocks - kBlocksPerIndirect -
        kBlocksPerDoubleIndirect;
    const uint32_t triple_block = inode->i_block[14];
    const uint32_t dbl_block = get_block_idx(
        fs, triple_block, triple_block_idx / kBlocksPerDoubleIndirect);
    const uint32_t dbl_block_idx = triple_block_idx % kBlocksPerDoubleIndirect;
    const uint32_t indirect_block = get_block_idx(
        fs, dbl_block, dbl_block_idx / kBlocksPerIndirect);

    *indirect_block_out = indirect_block;
    *indirect_block_offset_out = dbl_block_idx % kBlocksPerIndirect;
    return 0;
  }
}

// Given an inode and a block number in that inode, return the absolute block
// number of that block (in the filesystem), or -errno on error.
static uint32_t get_inode_block(ext2fs_t* fs, ext2_inode_t* inode,
                                uint32_t inode_block) {
  const uint32_t kDirectBlocks = 12;
  if (inode_block < kDirectBlocks) {
    return inode->i_block[inode_block];
  } else {
    uint32_t indirect_block;
    uint32_t indirect_block_offset;
    int result = get_inode_indirect_block(
        fs, inode, inode_block, &indirect_block, &indirect_block_offset);
    KASSERT(result == 0);
    return get_block_idx(fs, indirect_block, indirect_block_offset);
  }
}

// Iterate over the dirents in the given inode (which must be a directory),
// calling the given function on each one.  If the function returns non-zero,
// then the iteration will end early.  The return value is the return value of
// the final function call.
//
// The function takes: the given argument, a pointer to the on-disk dirent (in
// little endian form), and the absolute offset of that dirent from the
// beginning of the directory inode.
typedef int (*inode_iter_func_t)(void*, ext2_dirent_t*, uint32_t);
static int dirent_iterate(ext2fs_t* fs, ext2_inode_t* inode, uint32_t offset,
                          inode_iter_func_t func, void* arg) {
  KASSERT(inode->i_mode & EXT2_S_IFDIR);

  // Look for an appropriate entry.
  uint32_t inode_block = offset / ext2_block_size(fs);
  while (offset < inode->i_size) {
    const uint32_t block = get_inode_block(fs, inode, inode_block);
    const uint32_t block_len = min(
        ext2_block_size(fs), inode->i_size - inode_block * ext2_block_size(fs));
    void* block_data = block_cache_get(fs->dev, block);
    if (!block_data) {
      return -ENOENT;
    }

    uint32_t block_idx = offset % ext2_block_size(fs);
    while (block_idx < block_len) {
      ext2_dirent_t* dirent = (ext2_dirent_t*)(block_data + block_idx);
      KASSERT(offset == inode_block * ext2_block_size(fs) + block_idx);
      KASSERT(dirent->rec_len >= ext2_dirent_min_size(dirent->name_len));
      const int result = func(arg, dirent, offset);
      if (result) {
        block_cache_put(fs->dev, block);
        return result;
      }
      block_idx += ltoh16(dirent->rec_len);
      offset += ltoh16(dirent->rec_len);
    }
    if (block_idx > block_len) {
      klogf("ext2: error: dirent spans multiple blocks\n");
      block_cache_put(fs->dev, block);
      return -EFAULT;
    }

    block_cache_put(fs->dev, block);
    inode_block++;
  }

  return 0;
}

// Find and allocate N free blocks, preferably in the same block group as the
// given inode.  Returns 0 on success, or -errno on error.
// TODO(aoates): combine this and allocate_inode into a single function for
// finding free nodes in a block group's bitmap.
static int allocate_blocks(ext2fs_t* fs, uint32_t inode_num, uint32_t nblocks,
                           uint32_t* blocks_out) {
  if (fs->sb.s_free_blocks_count < nblocks) {
    return -ENOSPC;
  }

  // Starting with the inode's block group, look for one with enough free
  // blocks.
  uint32_t bg = (inode_num - 1) / fs->sb.s_inodes_per_group;
  unsigned int block_groups_checked = 0;
  while (fs->block_groups[bg].bg_free_blocks_count < nblocks &&
         block_groups_checked < fs->num_block_groups) {
    block_groups_checked++;
    bg = (bg + 1) % fs->num_block_groups;
  }
  // TODO(aoates): allocate the blocks amongst several block groups.
  if (block_groups_checked == fs->num_block_groups) {
    klogf("ext2 warning: no block groups found with %d free blocks\n", nblocks);
    return -ENOSPC;
  }

  // Decrement the free block count in the superblock and bgd, then flush them.
  KASSERT(fs->block_groups[bg].bg_free_blocks_count >= nblocks);
  fs->sb.s_free_blocks_count -= nblocks;
  fs->block_groups[bg].bg_free_blocks_count -= nblocks;
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  // Find the actual free blocks in the bitmap.
  uint8_t* block_bitmap = block_cache_get(fs->dev, fs->block_groups[bg].bg_block_bitmap);
  if (!block_bitmap) {
    // TODO(aoates): roll back the decrement of the counters.
    return -ENOMEM;
  }
  for (unsigned int i = 0; i < nblocks; ++i) {
    int idx_in_bg_bmp = bg_bitmap_find_free(fs, block_bitmap);
    if (idx_in_bg_bmp < 0) {
      block_cache_put(fs->dev, fs->block_groups[bg].bg_block_bitmap);
      klogf("ext2 warning: block group desc indicated free blocks, but none "
            "found in block bitmap!\n");
      fs->unhealthy = 1;
      return -ENOSPC;
    }
    bg_bitmap_set(block_bitmap, idx_in_bg_bmp);
    blocks_out[i] = fs->sb.s_first_data_block + bg * fs->sb.s_blocks_per_group +
        idx_in_bg_bmp;
  }
  block_cache_put(fs->dev, fs->block_groups[bg].bg_block_bitmap);
  return 0;
}

// Free the given block.
static int free_block(ext2fs_t* fs, uint32_t block) {
  const uint32_t bg = get_block_bg(fs, block);
  const uint32_t bg_block_idx = get_block_bg_idx(fs, block);

  // Increment the free block count in the superblock and bgd, then flush them.
  fs->sb.s_free_blocks_count++;
  fs->block_groups[bg].bg_free_blocks_count++;
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  // Mark the block as free in the bitmap
  uint8_t* block_bitmap = block_cache_get(fs->dev, fs->block_groups[bg].bg_block_bitmap);
  if (!block_bitmap) {
    return -ENOMEM;
  }
  KASSERT(bg_bitmap_get(fs, block_bitmap, bg_block_idx));
  bg_bitmap_clear(block_bitmap, bg_block_idx);
  block_cache_put(fs->dev, fs->block_groups[bg].bg_block_bitmap);

  return 0;
}

// Allocate a new inode.  Depending on the type, it may be allocated in the
// parent's block group, or another block group.
//
// Marks the inode as in-use in the inode bitmap of the chosen block group, and
// returns the new inode's number.  Returns -errno (and doesn't mark any inodes
// as in-use) on error.
static int allocate_inode(ext2fs_t* fs, uint32_t parent_inode, uint32_t mode) {
  if (fs->sb.s_free_inodes_count == 0) {
    return -ENOSPC;
  }

  // If we're not creating a directory, try to allocate in the parent's bg.
  // TODO(aoates): choose a random block group!
  uint32_t bg = ((mode & EXT2_S_IFDIR) == 0) ?
      ((parent_inode - 1) / fs->sb.s_inodes_per_group) : 0;

  // Starting with bg, find a block group with a free inode.
  unsigned int block_groups_checked = 0;
  while (fs->block_groups[bg].bg_free_inodes_count == 0 &&
         block_groups_checked < fs->num_block_groups) {
    block_groups_checked++;
    bg = (bg + 1) % fs->num_block_groups;
  }
  if (block_groups_checked == fs->num_block_groups) {
    klogf("ext2 warning: superblock indicated free inodes, but none found "
          "in block groups!\n");
    fs->unhealthy = 1;
    return -ENOSPC;
  }

  // Decrement the free inode count in the superblock and bgd, then flush them.
  KASSERT(fs->block_groups[bg].bg_free_inodes_count > 0);
  fs->sb.s_free_inodes_count--;
  fs->block_groups[bg].bg_free_inodes_count--;
  if (mode & EXT2_S_IFDIR) {
    fs->block_groups[bg].bg_used_dirs_count++;
  }
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  // Find the actual free inode in the bitmap.
  uint8_t* inode_bitmap = block_cache_get(fs->dev, fs->block_groups[bg].bg_inode_bitmap);
  if (!inode_bitmap) {
    // TODO(aoates): roll back the decrement of the counters.
    return -ENOMEM;
  }
  int idx_in_bg = bg_bitmap_find_free(fs, inode_bitmap);
  if (idx_in_bg < 0) {
    block_cache_put(fs->dev, fs->block_groups[bg].bg_inode_bitmap);
    klogf("ext2 warning: block group desc indicated free inodes, but none found "
          "in inode bitmap!\n");
    fs->unhealthy = 1;
    return -ENOSPC;
  }

  // Mark the inode as used and return it's index.
  bg_bitmap_set(inode_bitmap, idx_in_bg);
  block_cache_put(fs->dev, fs->block_groups[bg].bg_inode_bitmap);

  // Inode numbers are 1-indexed.
  const int inode = bg * fs->sb.s_inodes_per_group + idx_in_bg + 1;
  return inode;
}

// Free the given inode and associated data blocks.  The inode's links_count
// must be 0.  Returns 0 on success.
static int free_inode(ext2fs_t* fs, uint32_t inode_num, ext2_inode_t* inode) {
  KASSERT(inode->i_links_count == 0);

  const uint32_t bg = get_inode_bg(fs, inode_num);
  const uint32_t bg_inode_idx = get_inode_bg_idx(fs, inode_num);

  // Increment the free inode count in the superblock and bgd, then flush them.
  fs->sb.s_free_inodes_count++;
  fs->block_groups[bg].bg_free_inodes_count++;
  if (inode->i_mode & EXT2_S_IFDIR) {
    fs->block_groups[bg].bg_used_dirs_count--;
  }
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  // Mark the inode as free in the bitmap
  uint8_t* inode_bitmap = block_cache_get(fs->dev, fs->block_groups[bg].bg_inode_bitmap);
  if (!inode_bitmap) {
    return -ENOMEM;
  }
  KASSERT(bg_bitmap_get(fs, inode_bitmap, bg_inode_idx));
  bg_bitmap_clear(inode_bitmap, bg_inode_idx);
  block_cache_put(fs->dev, fs->block_groups[bg].bg_inode_bitmap);

  // Free all of its blocks.
  // TODO(aoates): this is a bit lenient in case there are holes, but is that
  // actually possible?
  // TODO(aoates): this is a ridiculously inefficient way to do this (since it
  // requires deref'ing the indirect blocks each time).
  uint32_t blocks_to_free = inode->i_blocks / (2 << fs->sb.s_log_block_size);
  uint32_t inode_block = 0;
  // TODO(aoates): should also verify that inode_blocks won't exceed the maximum
  // number of blocks.
  while (blocks_to_free > 0) {
    const uint32_t block_to_free = get_inode_block(fs, inode, inode_block);
    inode_block++;
    if (block_to_free != 0) {
      int result = free_block(fs, block_to_free);
      if (result) {
        return result;
      }
      blocks_to_free--;
    }
  }

  kmemset(inode, 0, sizeof(ext2_inode_t));
  write_inode(fs, inode_num, inode);
  return 0;
}

// Extend the given inode by N blocks, and updates it's size.  Returns 0 on
// success, or -errno on error.  On error, the no new blocks are allocated, and
// the size isn't updated.
static int extend_inode(ext2fs_t* fs, ext2_inode_t* inode, uint32_t inode_num,
                        unsigned int nblocks, uint32_t new_size) {
  const uint32_t kDirectBlocks = 12;
  const uint32_t kBlocksPerIndirect = ext2_block_size(fs) / sizeof(uint32_t);
  const uint32_t kBlocksPerDoubleIndirect =
      kBlocksPerIndirect * kBlocksPerIndirect;
  const uint32_t kBlocksPerTripleIndirect =
      kBlocksPerDoubleIndirect * kBlocksPerIndirect;
  const uint32_t kMaxBlocks = kDirectBlocks + kBlocksPerIndirect +
      kBlocksPerDoubleIndirect + kBlocksPerTripleIndirect;

  const uint32_t last_block = inode->i_blocks / (2 << fs->sb.s_log_block_size);
  if (last_block >= kMaxBlocks - nblocks) {
    return -EFBIG;
  }

  uint32_t* new_blocks = (uint32_t*)kmalloc(sizeof(uint32_t) * nblocks);
  int result = allocate_blocks(fs, inode_num, nblocks, new_blocks);
  if (result) {
    kfree(new_blocks);
    return result;
  }

  uint32_t inode_block = last_block;
  for (unsigned int i = 0; i < nblocks; ++i) {
    if (inode_block < kDirectBlocks) {
      KASSERT(inode->i_block[inode_block] == 0);
      inode->i_block[inode_block] = new_blocks[i];
    } else {
      uint32_t indirect_block;
      uint32_t indirect_block_offset;
      int result = get_inode_indirect_block(
          fs, inode, inode_block, &indirect_block, &indirect_block_offset);
      KASSERT(result == 0);
      set_block_idx(fs, indirect_block, indirect_block_offset,
                    new_blocks[i]);
    }
    inode_block++;
  }
  kfree(new_blocks);

  inode->i_blocks += nblocks * (ext2_block_size(fs) / 512);
  KASSERT(new_size >= inode->i_size);
  inode->i_size = new_size;
  return write_inode(fs, inode_num, inode);
}

typedef struct {
  const char* name;
  int name_len;
  uint32_t inode_out;
  uint32_t offset_out;
} ext2_lookup_iter_arg_t;
static int ext2_lookup_iter_func(void* arg, ext2_dirent_t* little_endian_dirent,
                                 uint32_t offset) {
  ext2_lookup_iter_arg_t* lookup_args = (ext2_lookup_iter_arg_t*)arg;

  const uint32_t inode = ltoh32(little_endian_dirent->inode);
  if (inode != 0 &&
      little_endian_dirent->name_len == lookup_args->name_len &&
      kstrncmp(little_endian_dirent->name, lookup_args->name,
               lookup_args->name_len) == 0) {
    lookup_args->inode_out = inode;
    lookup_args->offset_out = offset;
    return 1;
  }
  return 0;
}

// Look up the given name in the parent, and return it's inode and its offset of
// the dirent_t within the parent inode.  Returns 0 on success, -errno on error.
// TODO(aoates): support filetype extension, and return it here.
// TODO(aoates): make this take a const ext2_inode_t*.
static int lookup_internal(ext2fs_t* fs, ext2_inode_t* parent_inode,
                           const char* name, uint32_t* inode_out,
                           uint32_t* offset_out) {
  KASSERT(parent_inode->i_mode & EXT2_S_IFDIR);

  ext2_lookup_iter_arg_t arg;
  arg.name = name;
  arg.name_len = kstrlen(name);
  arg.inode_out = arg.offset_out = 0;

  int result =
      dirent_iterate(fs, parent_inode, 0, &ext2_lookup_iter_func, &arg);
  if (result) {
    KASSERT(arg.inode_out > 0);
    KASSERT(arg.offset_out < parent_inode->i_size);
    if (inode_out) *inode_out = arg.inode_out;
    if (offset_out) *offset_out = arg.offset_out;
    return 0;
  } else {
    return -ENOENT;
  }
}

typedef struct {
  uint32_t new_rec_len;
  uint32_t offset;
} link_internal_iter_t;
static int link_internal_iter_func(
    void* arg, ext2_dirent_t* little_endian_dirent, uint32_t offset) {
  link_internal_iter_t* link_arg = (link_internal_iter_t*)arg;
  // See if the new link could fit into this dirent.
  const uint16_t min_rec_len =
      (little_endian_dirent->inode == 0 ? 0 :
       ext2_dirent_min_size(little_endian_dirent->name_len));
  if (min_rec_len + link_arg->new_rec_len <=
      ltoh16(little_endian_dirent->rec_len)) {
    link_arg->offset = offset;
    return offset + 1;
  }
  return 0;
}
// Create a link in the given parent directory to the given inode with the given
// name.  Doesn't look up the child inode to verify it's existence or increment
// it's link count.
//
// Note: the caller must update any vnodes for the parent with it's (potentially
// new) size.
static int link_internal(ext2fs_t* fs, ext2_inode_t* parent,
                         uint32_t parent_inode, const char* name,
                         uint32_t inode) {
  KASSERT(parent->i_mode & EXT2_S_IFDIR);
  const uint32_t block_size = ext2_block_size(fs);

  const int name_len = kstrlen(name);
  KASSERT(name_len <= 255);
  link_internal_iter_t iter_arg;
  iter_arg.new_rec_len = ext2_dirent_min_size(name_len);
  iter_arg.offset = 0;

  int result =
      dirent_iterate(fs, parent, 0, &link_internal_iter_func, &iter_arg);
  int new_block_created = 0;
  if (!result) {
    // Round the current size up to a round block size, then add a block.
    uint32_t new_size =
        (ceiling_div(parent->i_size, block_size) + 1) * block_size;
    result = extend_inode(fs, parent, parent_inode, 1, new_size);
    if (result) {
      return result;
    }
    // Put the new dirent at the start of the new block.
    iter_arg.offset = parent->i_size - block_size;
    KASSERT(iter_arg.offset % block_size == 0);
    new_block_created = 1;
  }

  klogf("ext2 link_internal: splitting inode at offset %d\n", iter_arg.offset);
  const uint32_t inode_block = iter_arg.offset / block_size;
  const uint32_t block_offset = iter_arg.offset % block_size;
  const uint32_t block_num = get_inode_block(fs, parent, inode_block);
  void* block = block_cache_get(fs->dev, block_num);
  if (!block) {
    return -ENOMEM;
  }

  ext2_dirent_t* new_dirent = 0x0;
  uint16_t new_dirent_len = 0;
  // If we didn't create a new block, split the existing dirent.
  if (new_block_created) {
    new_dirent = block;
    new_dirent_len = block_size;
  } else {
    ext2_dirent_t* dirent_to_split = (ext2_dirent_t*)(block + block_offset);
    const uint16_t first_dirent_len =
        (dirent_to_split->inode == 0) ? 0 :
        ext2_dirent_min_size(dirent_to_split->name_len);
    new_dirent_len = ltoh16(dirent_to_split->rec_len) - first_dirent_len;
    KASSERT(new_dirent_len >= ext2_dirent_min_size(name_len));
    if (first_dirent_len > 0) {
      dirent_to_split->rec_len = htol16(first_dirent_len);
    }

    new_dirent = (ext2_dirent_t*)(block + block_offset + first_dirent_len);
  }
  new_dirent->inode = htol32(inode);
  new_dirent->rec_len = htol16(new_dirent_len);
  new_dirent->name_len = name_len;
  // TODO(aoates): use filetype extension.
  new_dirent->file_type = EXT2_FT_UNKNOWN;
  kstrncpy(new_dirent->name, name, name_len);

  block_cache_put(fs->dev, block_num);
  return 0;
}

// Unlink the given entry in the parent.  Does NOT update the link count of the
// child.
static int unlink_internal(ext2fs_t* fs, ext2_inode_t* parent,
                           const char* name) {
  KASSERT(parent->i_mode & EXT2_S_IFDIR);
  const uint32_t block_size = ext2_block_size(fs);

  // Lookup the child and find its dirent.
  uint32_t child_inode, child_offset;
  int result = lookup_internal(fs, parent, name, &child_inode, &child_offset);
  if (result) {
    return result;
  }

  const uint32_t inode_block = child_offset / block_size;
  const uint32_t block_offset = child_offset % block_size;
  const uint32_t block_num = get_inode_block(fs, parent, inode_block);
  void* block = block_cache_get(fs->dev, block_num);
  if (!block) {
    return -ENOMEM;
  }

  // Mark the dirent as unused.
  ext2_dirent_t* child_dirent = (ext2_dirent_t*)(block + block_offset);
  KASSERT_DBG(ltoh32(child_dirent->inode) == child_inode);
  KASSERT_DBG(kstrncmp(child_dirent->name, name, child_dirent->name_len) == 0);
  child_dirent->inode = 0;
  child_dirent->name_len = 0;
  child_dirent->file_type = 0;

  // TODO(aoates): check if previous and/or next dirents are also free, and
  // merge them with this one if so.
  block_cache_put(fs->dev, block_num);
  return 0;
}

// Allocate and initialize a new inode, given the inode number of the parent
// (used to select a block group) and it's mode.
//
// On success, writes the new inode to disk, copies its data into
// child_inode_out, and returns the inode number.
// Returns -errno on error.
static int make_inode(ext2fs_t* fs, uint32_t parent_inode, uint16_t mode,
                      ext2_inode_t* child_inode_out) {
  // First allocate a new inode for the new file.
  const int child_inode_num = allocate_inode(fs, parent_inode, mode);
  KASSERT(child_inode_num < 0 ||
          (uint32_t)child_inode_num >= fs->sb.s_first_ino);
  if (child_inode_num < 0) {
    return child_inode_num;
  }

  int result = get_inode(fs, child_inode_num, child_inode_out);
  if (result) {
    // TODO(aoates): free the allocated inode
    return result;
  }

  // Fill the new inode and write it back to disk.
  kmemset(child_inode_out, 0, sizeof(ext2_inode_t));
  child_inode_out->i_mode = mode;
  child_inode_out->i_size = 0;
  child_inode_out->i_links_count = 1;
  result = write_inode(fs, child_inode_num, child_inode_out);
  if (result) {
    // TODO(aoates): free the allocated inode
    return result;
  }

  return child_inode_num;
}

void ext2_set_ops(fs_t* fs) {
  fs->alloc_vnode = &ext2_alloc_vnode;
  fs->get_root = &ext2_get_root;
  fs->get_vnode = &ext2_get_vnode;
  fs->put_vnode = &ext2_put_vnode;
  fs->lookup = &ext2_lookup;
  fs->create = &ext2_create;
  fs->mkdir = &ext2_mkdir;
  fs->rmdir = &ext2_rmdir;
  fs->read = &ext2_read;
  fs->write = &ext2_write;
  fs->link = &ext2_link;
  fs->unlink = &ext2_unlink;
  fs->getdents = &ext2_getdents;
}

static vnode_t* ext2_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int ext2_get_root(struct fs* fs) {
  return EXT2_ROOT_INO;
}

static int ext2_get_vnode(vnode_t* vnode) {
  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  kstrcpy(vnode->fstype, "ext2");
  // Fill in the vnode_t with data from the filesystem.  The vnode_t will have
  // been allocated with alloc_vnode and had the following fields initalized:
  // num, refcount, fs, mutex.  The FS should initialize the remaining fields
  // (and any FS-specific fields), and return 0 on success, or -errno on
  // failure.
  ext2_inode_t inode;
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }

  if (inode.i_mode & EXT2_S_IFREG) {
    vnode->type = VNODE_REGULAR;
    // Don't support large files.
    KASSERT(inode.i_dir_acl == 0);
  } else if (inode.i_mode & EXT2_S_IFDIR) {
    vnode->type = VNODE_DIRECTORY;
  } else {
    klogf("ext2: unsupported inode type: 0x%x\n", inode.i_mode);
    return -ENOTSUP;
  }
  vnode->len = inode.i_size;
  return 0;
}

static int ext2_put_vnode(vnode_t* vnode) {
  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);

  ext2_inode_t inode;
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }

  switch (vnode->type) {
    case VNODE_REGULAR: KASSERT(inode.i_mode & EXT2_S_IFREG); break;
    case VNODE_DIRECTORY: KASSERT(inode.i_mode & EXT2_S_IFDIR); break;
  }

  inode.i_size = vnode->len;
  result = write_inode(fs, vnode->num, &inode);
  return result;
}

static int ext2_lookup(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(parent->fstype, "ext2") == 0);

  ext2fs_t* fs = (ext2fs_t*)parent->fs;
  ext2_inode_t inode;
  int result = get_inode(fs, parent->num, &inode);
  if (result) {
    return result;
  }

  uint32_t child_inode;
  result = lookup_internal(fs, &inode, name, &child_inode, 0x0);
  if (result) {
    return result;
  } else {
    return child_inode;
  }
}

static int ext2_create(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(parent->fstype, "ext2") == 0);

  ext2fs_t* fs = (ext2fs_t*)parent->fs;
  if (fs->read_only) {
    return -EROFS;
  }

  ext2_inode_t parent_inode;
  // TODO(aoates): do we want to store the inode in the vnode?
  int result = get_inode(fs, parent->num, &parent_inode);
  if (result) {
    return result;
  }

  result = lookup_internal(fs, &parent_inode, name, 0x0, 0x0);
  if (result == 0) {
    return -EEXIST;
  } else if (result != -ENOENT) {
    return result;
  }

  ext2_inode_t child_inode;
  const int child_inode_num =
      make_inode(fs, parent->num, EXT2_S_IFREG, &child_inode);
  if (child_inode_num < 0) {
    return child_inode_num;
  }

  // Link it into the directory.
  result = link_internal(fs, &parent_inode, parent->num, name, child_inode_num);
  parent->len = parent_inode.i_size;
  if (result) {
    // TODO(aoates): free the allocated inode
    return result;
  }

  return child_inode_num;
}

static int ext2_mkdir(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(parent->fstype, "ext2") == 0);

  ext2fs_t* fs = (ext2fs_t*)parent->fs;
  if (fs->read_only) {
    return -EROFS;
  }

  ext2_inode_t parent_inode;
  // TODO(aoates): do we want to store the inode in the vnode?
  int result = get_inode(fs, parent->num, &parent_inode);
  if (result) {
    return result;
  }

  result = lookup_internal(fs, &parent_inode, name, 0x0, 0x0);
  if (result == 0) {
    return -EEXIST;
  } else if (result != -ENOENT) {
    return result;
  }

  ext2_inode_t child_inode;
  const int child_inode_num =
      make_inode(fs, parent->num, EXT2_S_IFDIR, &child_inode);
  if (child_inode_num < 0) {
    return child_inode_num;
  }

  // Link it to itself and it's parent.
  result = link_internal(fs, &child_inode, child_inode_num,
                         ".", child_inode_num);
  if (result) {
    return result;
  }
  result = link_internal(fs, &child_inode, child_inode_num, "..", parent->num);
  if (result) {
    return result;
  }

  // Fix up link counts.
  parent_inode.i_links_count++;
  child_inode.i_links_count++;
  write_inode(fs, parent->num, &parent_inode);
  write_inode(fs, child_inode_num, &child_inode);

  // Link it into the directory.
  result = link_internal(fs, &parent_inode, parent->num, name, child_inode_num);
  parent->len = parent_inode.i_size;
  if (result) {
    // TODO(aoates): free the allocated inode
    return result;
  }

  return child_inode_num;
}

static int ext2_rmdir_iter_func(void* arg,
                                ext2_dirent_t* dirent,
                                uint32_t offset) {
  if (dirent->inode != 0 &&
      kstrncmp(dirent->name, ".", dirent->name_len) != 0 &&
      kstrncmp(dirent->name, "..", dirent->name_len) != 0) {
    return 1;
  }
  return 0;
}

static int ext2_rmdir(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(parent->fstype, "ext2") == 0);

  // Get the parent inode.
  ext2fs_t* fs = (ext2fs_t*)parent->fs;
  ext2_inode_t parent_inode;
  int result = get_inode(fs, parent->num, &parent_inode);
  if (result)
    return result;
  KASSERT(parent_inode.i_mode & EXT2_S_IFDIR);

  // Get the child inode.
  const int child_inode_num = ext2_lookup(parent, name);
  if (child_inode_num < 0) return child_inode_num;

  ext2_inode_t child_inode;
  result = get_inode(fs, child_inode_num, &child_inode);
  if (result) return result;
  if ((child_inode.i_mode & EXT2_S_IFDIR) == 0)
    return -ENOTDIR;

  // Make sure it is empty.
  result = dirent_iterate(fs, &child_inode, 0, &ext2_rmdir_iter_func, 0x0);
  if (result)
    return -ENOTEMPTY;

  // Can't hard link directories, so should just be 2 links.
  KASSERT(child_inode.i_links_count == 2);

  result = unlink_internal(fs, &parent_inode, name);
  if (result)
    return result;

  // Update link counts.
  parent_inode.i_links_count--;
  write_inode(fs, parent->num, &parent_inode);

  child_inode.i_links_count -= 2;
  result = free_inode(fs, child_inode_num, &child_inode);
  return result;
}

static int ext2_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_REGULAR);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);
  KASSERT(offset >= 0);
  KASSERT(offset <= vnode->len);

  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  const uint32_t inode_block = offset / ext2_block_size(fs);
  const uint32_t block_offset = offset % ext2_block_size(fs);

  // How many bytes we'll actually read.
  const int len = min(bufsize, min(
          vnode->len - offset,
          (int)ext2_block_size(fs) - (int)block_offset));
  if (len == 0) {
    return 0;
  }

  ext2_inode_t inode;
  // TODO(aoates): do we want to store the inode in the vnode?
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }
  const uint32_t block = get_inode_block(fs, &inode, inode_block);
  KASSERT(block > 0);

  void* block_data = block_cache_get(fs->dev, block);
  if (!block_data) {
    return -ENOENT;
  }
  KASSERT_DBG(block_offset + len <= ext2_block_size(fs));
  KASSERT_DBG(len <= bufsize);
  kmemcpy(buf, block_data + block_offset, len);

  block_cache_put(fs->dev, block);
  return len;
}

static int ext2_write(vnode_t* vnode, int offset,
                      const void* buf, int bufsize) {
  return -EROFS;
}

static int ext2_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  return -EROFS;
}

static int ext2_unlink(vnode_t* parent, const char* name) {
  return -EROFS;
}

typedef struct {
  void* buf;
  int bufsize;
  dirent_t* last_dirent;  // The last dirent we put into the buffer.
} ext2_getdents_iter_arg_t;
static int ext2_getdents_iter_func(void* arg,
                                   ext2_dirent_t* little_endian_dirent,
                                   uint32_t offset) {
  ext2_getdents_iter_arg_t* getdents_args = (ext2_getdents_iter_arg_t*)arg;

  // Skip empty entries.
  if (little_endian_dirent->inode == 0) {
    return 0;
  }

  // Update the offset of the *last* dirent we wrote to the current offset.
  if (getdents_args->last_dirent) {
    getdents_args->last_dirent->offset = offset;
  }

  const int dirent_out_size =
      sizeof(dirent_t) + little_endian_dirent->name_len + 1;
  if (dirent_out_size > getdents_args->bufsize) {
    // Out of room, we're done.
    return 1;
  }

  dirent_t* dirent_out = (dirent_t*)getdents_args->buf;
  dirent_out->vnode = ltoh32(little_endian_dirent->inode);
  dirent_out->offset = -1;  // We'll update this in the next iteration.
  dirent_out->length = dirent_out_size;
  kstrncpy(dirent_out->name, little_endian_dirent->name,
           little_endian_dirent->name_len);
  dirent_out->name[little_endian_dirent->name_len] = '\0';

  getdents_args->buf += dirent_out_size;
  getdents_args->bufsize -= dirent_out_size;
  getdents_args->last_dirent = dirent_out;
  return 0;
}

static int ext2_getdents(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);

  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  ext2_inode_t inode;
  // TODO(aoates): do we want to store the inode in the vnode?
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }

  ext2_getdents_iter_arg_t arg;
  arg.buf = buf;
  arg.bufsize = bufsize;
  arg.last_dirent = 0x0;

  result = dirent_iterate(fs, &inode, offset, &ext2_getdents_iter_func, &arg);

  if (result) {
    if (arg.last_dirent) {
      KASSERT(arg.last_dirent->offset >= offset);
    }
  } else if (arg.last_dirent != 0x0) {
    // If we went through all the dirents possible, set the offset to the end of
    // the file.
    KASSERT(arg.last_dirent->offset == -1);
    arg.last_dirent->offset = vnode->len;
  }
  return bufsize - arg.bufsize;
}
