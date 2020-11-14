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

#include "arch/common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/block_cache.h"
#include "memory/kmalloc.h"
#include "user/include/apos/vfs/dirent.h"
#include "vfs/fs.h"

#include "vfs/ext2/ext2-internal.h"
#include "vfs/ext2/ext2fs.h"

#define KLOG(...) klogfm(KL_EXT2, __VA_ARGS__)

#define EXT2_SYMLINK_INLINE_LEN 60

static vnode_t* ext2_alloc_vnode(struct fs* fs);
static int ext2_get_root(struct fs* fs);
static int ext2_get_vnode(vnode_t* vnode);
static int ext2_put_vnode(vnode_t* vnode);
static int ext2_lookup(vnode_t* parent, const char* name);
static int ext2_mknod(vnode_t* parent, const char* name,
                      vnode_type_t type, apos_dev_t dev);
static int ext2_mkdir(vnode_t* parent, const char* name);
static int ext2_rmdir(vnode_t* parent, const char* name);
static int ext2_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int ext2_write(vnode_t* vnode, int offset, const void* buf, int bufsize);
static int ext2_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int ext2_unlink(vnode_t* parent, const char* name);
static int ext2_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
static int ext2_stat(vnode_t* vnode, apos_stat_t* stat_out);
static int ext2_symlink(vnode_t* parent, const char* name, const char* path);
static int ext2_readlink(vnode_t* node, char* buf, int bufsize);
static int ext2_truncate(vnode_t* node, koff_t length);
static int ext2_read_page(vnode_t* vnode, int page_offset, void* buf);
static int ext2_write_page(vnode_t* vnode, int page_offset, const void* buf);

// Given a block-sized bitmap (i.e. a block group's block or inode bitmap),
// return the value of the Nth entry.
static inline int bg_bitmap_get(const void* bitmap, int n) {
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
static int bg_bitmap_find_free(const ext2fs_t* fs, const uint8_t* bitmap) {
  kmutex_assert_is_held(&fs->mu);
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
static inline int get_inode_bg(const ext2fs_t* fs, uint32_t inode_num) {
  return (inode_num - 1) / fs->sb.s_inodes_per_group;
}
static inline int get_inode_bg_idx(const ext2fs_t* fs, uint32_t inode_num) {
  return (inode_num - 1) % fs->sb.s_inodes_per_group;
}

// Return the block group that the given block is in.
static inline int get_block_bg(const ext2fs_t* fs, uint32_t block_num) {
  return (block_num - fs->sb.s_first_data_block) / fs->sb.s_blocks_per_group;
}
static inline int get_block_bg_idx(const ext2fs_t* fs, uint32_t block_num) {
  return (block_num - fs->sb.s_first_data_block) % fs->sb.s_blocks_per_group;
}

// Helper for get_inode and write_inode.  Given an inode number, return (via out
// parameters) the inode's block group, the index of the inode within that block
// group, the block number of the corresponding inode bitmap, and the block
// number and byte index of the corresponding block in the appropriate block
// group's inode table.
// TODO(aoates): use this for allocate_inode as well.
static void get_inode_info(const ext2fs_t* fs, uint32_t inode_num,
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
static int get_inode(const ext2fs_t* fs, uint32_t inode_num,
                     ext2_inode_t* inode) {
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
  const void* inode_bitmap = ext2_block_get(fs, inode_bitmap_block);
  if (!inode_bitmap) {
    KLOG(WARNING, "ext2: couldn't get inode bitmap for block "
         "group %d (block %d)\n", block_group, inode_bitmap_block);
    return -ENOENT;
  }

  ext2fs_lock(fs);
  int bitmap_data = bg_bitmap_get(inode_bitmap, inode_bg_idx);
  ext2fs_unlock(fs);
  ext2_block_put(fs, inode_bitmap_block, BC_FLUSH_NONE);
  if (!bitmap_data) {
    return -ENOENT;
  }

  // We know that the inode is allocated, now get it from the inode table.
  const void* inode_table = ext2_block_get(fs, inode_table_block);
  if (!inode_table) {
    KLOG(WARNING, "ext2: couldn't get inode table for block "
         "group %d (block %d)\n", block_group, inode_table_block);
    return -ENOENT;
  }

  // TODO(aoates): we needto check the inode bitmap again!

  const ext2_inode_t* disk_inode = (const ext2_inode_t*)(
      inode_table + inode_table_offset);
  kmemcpy(inode, disk_inode, sizeof(ext2_inode_t));
  ext2_block_put(fs, inode_table_block, BC_FLUSH_NONE);

  ext2_inode_ltoh(inode);

  if (klog_enabled(KL_EXT2, DEBUG2)) {
    KLOG(DEBUG2, "inode %d:\n", inode_num);
    ext2_inode_log(DEBUG2, inode, 0);
  }

  return 0;
}

// Given an inode number and data, copy it back to disk.
static int write_inode(const ext2fs_t* fs, uint32_t inode_num,
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
  void* inode_table = ext2_block_get(fs, inode_table_block);
  if (!inode_table) {
    KLOG(WARNING, "ext2: couldn't get inode table for block "
         "group %d (block %d)\n", block_group, inode_table_block);
    return -ENOENT;
  }

  ext2_inode_t* disk_inode = (ext2_inode_t*)(
      inode_table + inode_table_offset);
  kmemcpy(disk_inode, inode, sizeof(ext2_inode_t));
  ext2_inode_ltoh(disk_inode);

  ext2_block_put(fs, inode_table_block, BC_FLUSH_ASYNC);
  return 0;
}

// Given a block number, return the ith uint32_t of that block.
static uint32_t read_block_u32(const ext2fs_t* fs, uint32_t block_num,
                               uint32_t idx) {
  KASSERT(block_num != 0);
  const void* block = ext2_block_get(fs, block_num);
  KASSERT(block);
  uint32_t value = ((const uint32_t*)block)[idx];
  ext2_block_put(fs, block_num, BC_FLUSH_NONE);
  return ltoh32(value);
}

// Given a block number, set the ith uint32_t of that block.
static void write_block_u32(const ext2fs_t* fs, uint32_t block_num,
                            uint32_t idx, uint32_t value) {
  KASSERT(block_num != 0);
  void* block = ext2_block_get(fs, block_num);
  KASSERT(block);
  ((uint32_t*)block)[idx] = htol32(value);
  ext2_block_put(fs, block_num, BC_FLUSH_ASYNC);
}

// Given an inode block index, return the level (0 for direct, 1 for indirect,
// etc), and the offset to get to that level (0 for direct, 12 for indirect, 12
// + 1024 for double indirect, etc).
static void get_inode_level_and_offset(const ext2fs_t* fs, uint32_t inode_block,
                                       int* level_out, uint32_t* offset_out) {
  const uint32_t kDirectBlocks = 12;
  const uint32_t kBlocksPerIndirect = ext2_block_size(fs) / sizeof(uint32_t);
  const uint32_t kBlocksPerDoubleIndirect =
      kBlocksPerIndirect * kBlocksPerIndirect;
  const uint32_t kBlocksPerTripleIndirect =
      kBlocksPerDoubleIndirect * kBlocksPerIndirect;

  if (inode_block < kDirectBlocks) {
    *level_out = 0;
    *offset_out = 0;
  } else if (inode_block < kDirectBlocks + kBlocksPerIndirect) {
    *level_out = 1;
    *offset_out = kDirectBlocks;
  } else if (inode_block < kDirectBlocks + kBlocksPerIndirect +
             kBlocksPerDoubleIndirect) {
    *level_out = 2;
    *offset_out = kDirectBlocks + kBlocksPerIndirect;
  } else {
    // Triply indirect block.
    KASSERT(inode_block < kDirectBlocks + kBlocksPerIndirect +
            kBlocksPerDoubleIndirect + kBlocksPerTripleIndirect);
    *level_out = 3;
    *offset_out = kDirectBlocks + kBlocksPerIndirect + kBlocksPerDoubleIndirect;
  }
}

// Given a base block, a level (>= 1), and an index within that level, return
// the indirect block containing that block's address (in *indirect_block_out)
// and the offset within that block (in *indirect_block_offset_out).
//
// If we reach a '0' block number before we get to the final level, we set the
// arguments and return early.  *level_out will be set to the last level that
// had a valid block number (which is level + 1 if base_block == 0).
static void get_indirect_block(const ext2fs_t* fs, int level,
                               uint32_t base_block, uint32_t index,
                               int* level_out,
                               uint32_t* indirect_block_out,
                               uint32_t* indirect_block_offset_out) {
  KASSERT(level > 0 && level <= 3);
  if (base_block == 0) {
    // We can't continue to dereference, so bail early.
    *level_out = level + 1;
    return;
  }

  const uint32_t kBlocksPerIndirect = ext2_block_size(fs) / sizeof(uint32_t);
  // How many blocks are (recursively) in this level.
  uint32_t blocks_in_next_level = 1;
  for (int i = 1; i < level; ++i) {
    blocks_in_next_level *= kBlocksPerIndirect;
  }
  if (level == 1) {
    KASSERT(index < kBlocksPerIndirect);
    *indirect_block_out = base_block;
    *indirect_block_offset_out = index;
    *level_out = level;
    return;
  } else {
    const uint32_t next_level_block_idx = index / blocks_in_next_level;
    const uint32_t next_level_index =
        index - (next_level_block_idx * blocks_in_next_level);
    *indirect_block_out = base_block;
    *indirect_block_offset_out = next_level_block_idx;
    *level_out = level;
    get_indirect_block(fs, level - 1,
                       read_block_u32(fs, base_block, next_level_block_idx),
                       next_level_index,
                       level_out,
                       indirect_block_out,
                       indirect_block_offset_out);
  }
}

// Given an inode and a block number in that inode, return the absolute block
// number of that block (in the filesystem), or -errno on error.
static uint32_t get_inode_block(const ext2fs_t* fs, const ext2_inode_t* inode,
                                uint32_t inode_block) {
  int level;
  uint32_t offset;
  get_inode_level_and_offset(fs, inode_block, &level, &offset);
  if (level == 0) {
    KASSERT_DBG(offset == 0);
    return inode->i_block[inode_block];
  } else {
    KASSERT(level <= 3);
    uint32_t indirect_block;
    uint32_t indirect_block_offset;
    int final_level;
    get_indirect_block(fs, level, inode->i_block[11 + level],
                       inode_block - offset,
                       &final_level,
                       &indirect_block,
                       &indirect_block_offset);
    if (final_level != 1) {
      //klogf("ext2: warning: cannot get block (%d) in unallocated indirect "
      //      "block (level %d)\n", inode_block, final_level);
      return 0;
    }

    return read_block_u32(fs, indirect_block, indirect_block_offset);
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
static int dirent_iterate(const ext2fs_t* fs, ext2_inode_t* inode,
                          uint32_t offset, inode_iter_func_t func, void* arg) {
  KASSERT((inode->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);

  // Look for an appropriate entry.
  uint32_t inode_block = offset / ext2_block_size(fs);
  while (offset < inode->i_size) {
    const uint32_t block = get_inode_block(fs, inode, inode_block);
    const uint32_t block_len = min(
        ext2_block_size(fs), inode->i_size - inode_block * ext2_block_size(fs));
    void* block_data = ext2_block_get(fs, block);
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
        ext2_block_put(fs, block, BC_FLUSH_ASYNC);
        return result;
      }
      block_idx += ltoh16(dirent->rec_len);
      offset += ltoh16(dirent->rec_len);
    }
    if (block_idx > block_len) {
      KLOG(ERROR, "ext2: dirent spans multiple blocks\n");
      ext2_block_put(fs, block, BC_FLUSH_ASYNC);
      return -EFAULT;
    }

    ext2_block_put(fs, block, BC_FLUSH_ASYNC);
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
  ext2fs_lock(fs);
  if (fs->sb.s_free_blocks_count < nblocks) {
    ext2fs_unlock(fs);
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
    ext2fs_unlock(fs);
    KLOG(WARNING, "ext2: no block groups found with %d free blocks\n", nblocks);
    return -ENOSPC;
  }

  // Decrement the free block count in the superblock and bgd, then flush them.
  KASSERT(fs->block_groups[bg].bg_free_blocks_count >= nblocks);
  fs->sb.s_free_blocks_count -= nblocks;
  fs->block_groups[bg].bg_free_blocks_count -= nblocks;

  // We've "reserved" our blocks; unlock and flush before figuring out which
  // blocks specifically in the group to allocate.
  ext2fs_unlock(fs);
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  // Find the actual free blocks in the bitmap.
  uint8_t* block_bitmap = ext2_block_get(fs, fs->block_groups[bg].bg_block_bitmap);
  if (!block_bitmap) {
    // TODO(aoates): roll back the decrement of the counters.
    return -ENOMEM;
  }

  ext2fs_lock(fs);
  for (unsigned int i = 0; i < nblocks; ++i) {
    int idx_in_bg_bmp = bg_bitmap_find_free(fs, block_bitmap);
    if (idx_in_bg_bmp < 0) {
      ext2fs_unlock(fs);
      ext2_block_put(fs, fs->block_groups[bg].bg_block_bitmap, BC_FLUSH_NONE);
      KLOG(WARNING, "ext2: block group desc indicated free blocks, but none "
           "found in block bitmap!\n");
      fs->unhealthy = 1;
      return -ENOSPC;
    }
    bg_bitmap_set(block_bitmap, idx_in_bg_bmp);
    blocks_out[i] = fs->sb.s_first_data_block + bg * fs->sb.s_blocks_per_group +
        idx_in_bg_bmp;
  }
  ext2fs_unlock(fs);
  ext2_block_put(fs, fs->block_groups[bg].bg_block_bitmap, BC_FLUSH_ASYNC);
  return 0;
}

// Free the given block.
static int free_block(ext2fs_t* fs, uint32_t block) {
  const uint32_t bg = get_block_bg(fs, block);
  const uint32_t bg_block_idx = get_block_bg_idx(fs, block);

  // Mark the block as free in the bitmap
  uint8_t* block_bitmap = ext2_block_get(fs, fs->block_groups[bg].bg_block_bitmap);
  if (!block_bitmap) {
    return -ENOMEM;
  }
  ext2fs_lock(fs);
  KASSERT(bg_bitmap_get(block_bitmap, bg_block_idx));
  bg_bitmap_clear(block_bitmap, bg_block_idx);
  ext2_block_put(fs, fs->block_groups[bg].bg_block_bitmap, BC_FLUSH_ASYNC);

  // Increment the free block count in the superblock and bgd, then flush them.
  fs->sb.s_free_blocks_count++;
  fs->block_groups[bg].bg_free_blocks_count++;
  ext2fs_unlock(fs);
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  return 0;
}

// Free an n-th level indirect block, starting at blk_offset.
static void free_indirect_block(ext2fs_t* fs, uint32_t block_num, int level,
                                uint32_t blk_offset) {
  KASSERT(level >= 1);
  if (block_num == 0)
    return;

  uint32_t* block = ext2_block_get(fs, block_num);
  KASSERT(block);

  const uint32_t block_size = ext2_block_size(fs);
  const uint32_t kBlocksPerIndirect = block_size / sizeof(uint32_t);

  uint32_t blocks_per_entry = 1;
  for (int i = 1; i < level; ++i) blocks_per_entry *= kBlocksPerIndirect;

  for (unsigned int i = 0; i < kBlocksPerIndirect; ++i) {
    if ((i + 1) * blocks_per_entry <= blk_offset) continue;
    if (level == 1 && block[i] != 0) {
      free_block(fs, block[i]);
      block[i] = 0;
    } else if (level > 1) {
      free_indirect_block(fs, block[i], level - 1,
                          blk_offset % blocks_per_entry);
    }
  }
  ext2_block_put(fs, block_num, BC_FLUSH_ASYNC);
  if (blk_offset == 0)
    free_block(fs, block_num);  // Free the indirect block itself.
}

// Free the blocks from the given inode starting at blk_offset.
static void free_inode_blocks(ext2fs_t* fs, ext2_inode_t* inode,
                              uint32_t blk_offset) {
  const uint32_t block_size = ext2_block_size(fs);
  const uint32_t kDirectBlocks = 12;
  const uint32_t kBlocksPerIndirect = block_size / sizeof(uint32_t);
  const uint32_t kBlocksPerDoubleIndirect =
      kBlocksPerIndirect * kBlocksPerIndirect;

  for (int i = blk_offset; i < 12; ++i) {
    if (inode->i_block[i]) free_block(fs, inode->i_block[i]);
    inode->i_block[i] = 0;
  }
  blk_offset = (blk_offset < kDirectBlocks) ? 0 : blk_offset - kDirectBlocks;
  if (blk_offset < kBlocksPerIndirect)
    free_indirect_block(fs, inode->i_block[12], 1, blk_offset);
  if (blk_offset == 0) inode->i_block[12] = 0;

  blk_offset =
      (blk_offset < kBlocksPerIndirect) ? 0 : blk_offset - kBlocksPerIndirect;
  if (blk_offset < kBlocksPerDoubleIndirect)
    free_indirect_block(fs, inode->i_block[13], 2, blk_offset);
  if (blk_offset == 0) inode->i_block[13] = 0;

  blk_offset = (blk_offset < kBlocksPerDoubleIndirect)
                   ? 0
                   : blk_offset - kBlocksPerDoubleIndirect;
  free_indirect_block(fs, inode->i_block[14], 3, blk_offset);
  if (blk_offset == 0) inode->i_block[14] = 0;
}

// Allocate a new inode.  Depending on the type, it may be allocated in the
// parent's block group, or another block group.
//
// Marks the inode as in-use in the inode bitmap of the chosen block group, and
// returns the new inode's number.  Returns -errno (and doesn't mark any inodes
// as in-use) on error.
static int allocate_inode(ext2fs_t* fs, uint32_t parent_inode, uint32_t mode) {
  ext2fs_lock(fs);
  if (fs->sb.s_free_inodes_count == 0) {
    ext2fs_unlock(fs);
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
    ext2fs_unlock(fs);
    KLOG(WARNING, "ext2: superblock indicated free inodes, but none found "
         "in block groups!\n");
    fs->unhealthy = 1;
    return -ENOSPC;
  }

  // Decrement the free inode count in the superblock and bgd, then flush them.
  KASSERT(fs->block_groups[bg].bg_free_inodes_count > 0);
  fs->sb.s_free_inodes_count--;
  fs->block_groups[bg].bg_free_inodes_count--;
  if ((mode & EXT2_S_MASK) == EXT2_S_IFDIR) {
    fs->block_groups[bg].bg_used_dirs_count++;
  }

  // We've "reserved" the inode; unlock and flush before figuring out which
  // inode specifically to allocate.
  ext2fs_unlock(fs);
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  // Find the actual free inode in the bitmap.
  uint8_t* inode_bitmap = ext2_block_get(fs, fs->block_groups[bg].bg_inode_bitmap);
  if (!inode_bitmap) {
    // TODO(aoates): roll back the decrement of the counters.
    return -ENOMEM;
  }
  ext2fs_lock(fs);
  int idx_in_bg = bg_bitmap_find_free(fs, inode_bitmap);
  if (idx_in_bg < 0) {
    ext2fs_unlock(fs);
    ext2_block_put(fs, fs->block_groups[bg].bg_inode_bitmap, BC_FLUSH_NONE);
    KLOG(WARNING, "ext2: block group desc indicated free inodes, but none found "
         "in inode bitmap!\n");
    fs->unhealthy = 1;
    return -ENOSPC;
  }

  // Mark the inode as used and return it's index.
  bg_bitmap_set(inode_bitmap, idx_in_bg);
  ext2fs_unlock(fs);
  ext2_block_put(fs, fs->block_groups[bg].bg_inode_bitmap, BC_FLUSH_ASYNC);

  // Inode numbers are 1-indexed.
  const int inode = bg * fs->sb.s_inodes_per_group + idx_in_bg + 1;
  return inode;
}

// Returns 1 if a inode with the given mode has data blocks.
static int inode_has_data_blocks(const ext2_inode_t* inode) {
  return ((inode->i_mode & EXT2_S_MASK) == EXT2_S_IFREG ||
          (inode->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR ||
          ((inode->i_mode & EXT2_S_MASK) == EXT2_S_IFLNK &&
           inode->i_size >= EXT2_SYMLINK_INLINE_LEN));
}

// Free the given inode and associated data blocks.  The inode's links_count
// must be 0.  Returns 0 on success.
static int free_inode(ext2fs_t* fs, uint32_t inode_num, ext2_inode_t* inode) {
  KASSERT(inode->i_links_count == 0);

  const uint32_t bg = get_inode_bg(fs, inode_num);
  const uint32_t bg_inode_idx = get_inode_bg_idx(fs, inode_num);

  // Free all of its blocks.
  if (inode_has_data_blocks(inode)) {
    free_inode_blocks(fs, inode, 0);
  }
  const bool is_dir = ((inode->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);

  kmemset(inode, 0, sizeof(ext2_inode_t));
  write_inode(fs, inode_num, inode);
  inode = NULL;

  // Mark the inode as free in the bitmap
  uint8_t* inode_bitmap = ext2_block_get(fs, fs->block_groups[bg].bg_inode_bitmap);
  if (!inode_bitmap) {
    return -ENOMEM;
  }
  ext2fs_lock(fs);
  KASSERT(bg_bitmap_get(inode_bitmap, bg_inode_idx));
  bg_bitmap_clear(inode_bitmap, bg_inode_idx);
  ext2_block_put(fs, fs->block_groups[bg].bg_inode_bitmap, BC_FLUSH_ASYNC);

  // Increment the free inode count in the superblock and bgd, then flush them.
  fs->sb.s_free_inodes_count++;
  fs->block_groups[bg].bg_free_inodes_count++;
  if (is_dir) {
    fs->block_groups[bg].bg_used_dirs_count--;
  }
  ext2fs_unlock(fs);
  ext2_flush_superblock(fs);
  ext2_flush_block_group(fs, bg);

  return 0;
}

// Extend the given inode by N blocks, and updates it's size to the given value.
// Returns 0 on success, or -errno on error.  On error, the no new blocks are
// allocated, and the size isn't updated.
//
// If clear_new_blocks is set, the new blocks are loaded and zeroed out.
static int extend_inode(ext2fs_t* fs, ext2_inode_t* inode, uint32_t inode_num,
                        unsigned int nblocks, uint32_t new_size,
                        int clear_new_blocks) {
  const uint32_t block_size = ext2_block_size(fs);
  const uint32_t kDirectBlocks = 12;
  const uint32_t kBlocksPerIndirect = block_size / sizeof(uint32_t);
  const uint32_t kBlocksPerDoubleIndirect =
      kBlocksPerIndirect * kBlocksPerIndirect;
  const uint32_t kBlocksPerTripleIndirect =
      kBlocksPerDoubleIndirect * kBlocksPerIndirect;
  const uint32_t kMaxBlocks = kDirectBlocks + kBlocksPerIndirect +
      kBlocksPerDoubleIndirect + kBlocksPerTripleIndirect;

  const uint32_t num_blocks = inode->i_blocks / (2 << fs->sb.s_log_block_size);
  if (num_blocks >= kMaxBlocks - nblocks) {
    return -EFBIG;
  }

  uint32_t* new_blocks = (uint32_t*)kmalloc(sizeof(uint32_t) * nblocks);
  int result = allocate_blocks(fs, inode_num, nblocks, new_blocks);
  if (result) {
    kfree(new_blocks);
    return result;
  }

  uint32_t inode_block = inode->i_size / block_size;
  // Find the actual last block.
  // TODO(aoates): calculate this directly from i_blocks instead of this idiocy.
  while (get_inode_block(fs, inode, inode_block) != 0) {
    inode_block++;
  }

  unsigned int blocks_created = nblocks;  // We may allocate indirect blocks too
  for (unsigned int i = 0; i < nblocks; ++i) {
    int level;
    uint32_t offset;
    get_inode_level_and_offset(fs, inode_block, &level, &offset);
    if (level == 0) {
      KASSERT(inode->i_block[inode_block] == 0);
      inode->i_block[inode_block] = new_blocks[i];
    } else {
      KASSERT(level <= 3);
      uint32_t indirect_block;
      uint32_t indirect_block_offset;

      // Try to set the block in the lowest level possible, allocating indirect
      // blocks as needed.
      int final_level;
      get_indirect_block(fs, level, inode->i_block[11 + level],
                         inode_block - offset,
                         &final_level,
                         &indirect_block,
                         &indirect_block_offset);
      while (final_level != 1) {
        uint32_t new_indirect_block;
        result = allocate_blocks(fs, inode_num, 1, &new_indirect_block);
        blocks_created++;
        if (result) {
          kfree(new_blocks);
          return result;
        }

        // Zero out the new block.
        void* block = ext2_block_get(fs, new_indirect_block);
        if (!block) {
          kfree(new_blocks);
          return -ENOMEM;
        }
        kmemset(block, 0, block_size);
        ext2_block_put(fs, new_indirect_block, BC_FLUSH_ASYNC);

        if (final_level == level + 1) {
          KASSERT(inode->i_block[11 + level] == 0);
          inode->i_block[11 + level] = new_indirect_block;
        } else {
          write_block_u32(fs, indirect_block, indirect_block_offset,
                          new_indirect_block);
        }
        get_indirect_block(fs, level, inode->i_block[11 + level],
                           inode_block - offset,
                           &final_level,
                           &indirect_block,
                           &indirect_block_offset);
      }

      write_block_u32(fs, indirect_block, indirect_block_offset, new_blocks[i]);
    }
    if (clear_new_blocks) {
      // TODO(aoates): there's no actual need to read this from disk if it's not
      // in the cache.  Add an option to block_cache_get() that skips the
      // read.
      void* block = ext2_block_get(fs, new_blocks[i]);
      kmemset(block, 0, block_size);
      ext2_block_put(fs, new_blocks[i], BC_FLUSH_ASYNC);
    }
    inode_block++;
  }
  kfree(new_blocks);

  inode->i_blocks += blocks_created * (ext2_block_size(fs) / 512);
  KASSERT(new_size >= inode->i_size);
  inode->i_size = new_size;
  return write_inode(fs, inode_num, inode);
}

// Resize the given inode, either larger or smaller.
static int resize_inode(ext2fs_t* fs, ext2_inode_t* inode, uint32_t inode_num,
                        uint32_t new_size, int clear_new_blocks) {
  if (inode->i_size == new_size)
    return 0;

  const uint32_t block_size = ext2_block_size(fs);
  // TODO(aoates): this isn't quite right, since we may have pre-allocated
  // additional blocks.
  const uint32_t old_blocks = ceiling_div(inode->i_size, block_size);
  const uint32_t new_blocks = ceiling_div(new_size, block_size);

  if (new_size > inode->i_size) {
    if (old_blocks > 0 && (inode->i_size % block_size) > 0 &&
        clear_new_blocks) {
      // Clear the new data region in the last block.
      const uint32_t last_block = get_inode_block(fs, inode, old_blocks - 1);
      void* block = ext2_block_get(fs, last_block);
      kmemset((char*)block + inode->i_size % block_size, 0x0,
              block_size - (inode->i_size % block_size));
      ext2_block_put(fs, last_block, BC_FLUSH_ASYNC);
    }
    if (new_blocks > old_blocks) {
      int result = extend_inode(fs, inode, inode_num, new_blocks - old_blocks,
                                new_size, 1);
      if (result)
        return result;
    }
  } else if (new_size < inode->i_size) {
    if (new_blocks < old_blocks) {
      free_inode_blocks(fs, inode, new_blocks);
    }
  }
  inode->i_size = new_size;
  KASSERT(write_inode(fs, inode_num, inode) == 0);
  return 0;
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
static int lookup_internal(const ext2fs_t* fs, ext2_inode_t* parent_inode,
                           const char* name, uint32_t* inode_out,
                           uint32_t* offset_out) {
  KASSERT((parent_inode->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);

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
  KASSERT((parent->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);
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
    result = extend_inode(fs, parent, parent_inode, 1, new_size, 0);
    if (result) {
      return result;
    }
    // Put the new dirent at the start of the new block.
    iter_arg.offset = parent->i_size - block_size;
    KASSERT(iter_arg.offset % block_size == 0);
    new_block_created = 1;
  }

  const uint32_t inode_block = iter_arg.offset / block_size;
  const uint32_t block_offset = iter_arg.offset % block_size;
  const uint32_t block_num = get_inode_block(fs, parent, inode_block);
  void* block = ext2_block_get(fs, block_num);
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

  ext2_block_put(fs, block_num, BC_FLUSH_ASYNC);
  return 0;
}

// Unlink the given entry in the parent.  Does NOT update the link count of the
// child.
static int unlink_internal(ext2fs_t* fs, ext2_inode_t* parent,
                           const char* name) {
  KASSERT((parent->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);
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
  void* block = ext2_block_get(fs, block_num);
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
  ext2_block_put(fs, block_num, BC_FLUSH_ASYNC);
  return 0;
}

// Relink the given entry in the parent to the new inode.  Does NOT update the
// link count of the old or new child.
static int relink_internal(const ext2fs_t* fs, ext2_inode_t* parent,
                           const char* name, uint32_t new_inode,
                           uint32_t* old_inode_out) {
  KASSERT((parent->i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);
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
  void* block = ext2_block_get(fs, block_num);
  if (!block) {
    return -ENOMEM;
  }

  // Update the dirent.
  ext2_dirent_t* child_dirent = (ext2_dirent_t*)(block + block_offset);
  KASSERT_DBG(ltoh32(child_dirent->inode) == child_inode);
  KASSERT_DBG(kstrncmp(child_dirent->name, name, child_dirent->name_len) == 0);
  if (old_inode_out) *old_inode_out = ltoh32(child_dirent->inode);
  child_dirent->inode = htol32(new_inode);

  ext2_block_put(fs, block_num, BC_FLUSH_ASYNC);
  return 0;
}

// Extract a device from an inode (stored in the first block pointer).
static apos_dev_t ext2_get_device(const ext2_inode_t* inode) {
#if ENABLE_KERNEL_SAFETY_NETS
  const uint32_t type = inode->i_mode & EXT2_S_MASK;
  KASSERT_DBG((type == EXT2_S_IFBLK) || (type == EXT2_S_IFCHR));
#endif
  const int major = (inode->i_block[0] >> 16) & 0xFFFF;
  const int minor = inode->i_block[0] & 0xFFFF;
  return kmakedev(major, minor);
}

// Set the device for an inode.
static void ext2_set_device(ext2_inode_t* inode, apos_dev_t dev) {
#if ENABLE_KERNEL_SAFETY_NETS
  const uint32_t type = inode->i_mode & EXT2_S_MASK;
  KASSERT_DBG((type == EXT2_S_IFBLK) || (type == EXT2_S_IFCHR));
#endif
  const uint32_t block = (kmajor(dev) << 16) | (kminor(dev) & 0xFFFF);
  inode->i_block[0] = block;
}

// Allocate and initialize a new inode, given the inode number of the parent
// (used to select a block group) and it's mode.
//
// On success, writes the new inode to disk, copies its data into
// child_inode_out, and returns the inode number.
// Returns -errno on error.
static int make_inode(ext2fs_t* fs, uint32_t parent_inode, uint16_t mode,
                      apos_dev_t dev, ext2_inode_t* child_inode_out) {
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
  if (mode == EXT2_S_IFBLK || mode == EXT2_S_IFCHR) {
    ext2_set_device(child_inode_out, dev);
  }
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
  fs->mknod = &ext2_mknod;
  fs->mkdir = &ext2_mkdir;
  fs->rmdir = &ext2_rmdir;
  fs->read = &ext2_read;
  fs->write = &ext2_write;
  fs->link = &ext2_link;
  fs->unlink = &ext2_unlink;
  fs->getdents = &ext2_getdents;
  fs->stat = &ext2_stat;
  fs->symlink = &ext2_symlink;
  fs->readlink = &ext2_readlink;
  fs->truncate = &ext2_truncate;
  fs->read_page = &ext2_read_page;
  fs->write_page = &ext2_write_page;
}

static vnode_t* ext2_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int ext2_get_root(struct fs* fs) {
  return EXT2_ROOT_INO;
}

static int ext2_get_vnode(vnode_t* vnode) {
  const ext2fs_t* fs = (const ext2fs_t*)vnode->fs;
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

  if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFREG) {
    vnode->type = VNODE_REGULAR;
    // Don't support large files.
    KASSERT(inode.i_dir_acl == 0);
  } else if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFDIR) {
    vnode->type = VNODE_DIRECTORY;
  } else if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFBLK) {
    vnode->type = VNODE_BLOCKDEV;
    vnode->dev = ext2_get_device(&inode);
  } else if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFCHR) {
    vnode->type = VNODE_CHARDEV;
    vnode->dev = ext2_get_device(&inode);
  } else if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFLNK) {
    vnode->type = VNODE_SYMLINK;
  } else if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFIFO) {
    vnode->type = VNODE_FIFO;
  } else if ((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFSOCK) {
    vnode->type = VNODE_SOCKET;
  } else {
    KLOG(WARNING, "ext2: unsupported inode type: 0x%x\n", inode.i_mode);
    return -ENOTSUP;
  }

  vnode->mode = 0;
  if (inode.i_mode & EXT2_S_IRUSR) vnode->mode |= VFS_S_IRUSR;
  if (inode.i_mode & EXT2_S_IWUSR) vnode->mode |= VFS_S_IWUSR;
  if (inode.i_mode & EXT2_S_IXUSR) vnode->mode |= VFS_S_IXUSR;
  if (inode.i_mode & EXT2_S_IRGRP) vnode->mode |= VFS_S_IRGRP;
  if (inode.i_mode & EXT2_S_IWGRP) vnode->mode |= VFS_S_IWGRP;
  if (inode.i_mode & EXT2_S_IXGRP) vnode->mode |= VFS_S_IXGRP;
  if (inode.i_mode & EXT2_S_IROTH) vnode->mode |= VFS_S_IROTH;
  if (inode.i_mode & EXT2_S_IWOTH) vnode->mode |= VFS_S_IWOTH;
  if (inode.i_mode & EXT2_S_IXOTH) vnode->mode |= VFS_S_IXOTH;
  if (inode.i_mode & EXT2_S_ISUID) vnode->mode |= VFS_S_ISUID;
  if (inode.i_mode & EXT2_S_ISGID) vnode->mode |= VFS_S_ISGID;
  if (inode.i_mode & EXT2_S_ISVTX) vnode->mode |= VFS_S_ISVTX;

  vnode->len = inode.i_size;
  vnode->uid = inode.i_uid;
  vnode->gid = inode.i_gid;
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
    case VNODE_UNINITIALIZED:
    case VNODE_INVALID:
    case VNODE_MAX:
      die("ext2: invalid vnode type"); break;
    case VNODE_REGULAR:   KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFREG); break;
    case VNODE_DIRECTORY: KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFDIR); break;
    case VNODE_BLOCKDEV:  KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFBLK); break;
    case VNODE_CHARDEV:   KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFCHR); break;
    case VNODE_SYMLINK:   KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFLNK); break;
    case VNODE_FIFO:      KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFIFO); break;
    case VNODE_SOCKET:    KASSERT((inode.i_mode & EXT2_S_MASK) == EXT2_S_IFSOCK); break;
  }

  inode.i_mode &= EXT2_S_MASK;  // Clear non-type inode bits.
  if (vnode->mode & VFS_S_IRUSR) inode.i_mode |= EXT2_S_IRUSR;
  if (vnode->mode & VFS_S_IWUSR) inode.i_mode |= EXT2_S_IWUSR;
  if (vnode->mode & VFS_S_IXUSR) inode.i_mode |= EXT2_S_IXUSR;
  if (vnode->mode & VFS_S_IRGRP) inode.i_mode |= EXT2_S_IRGRP;
  if (vnode->mode & VFS_S_IWGRP) inode.i_mode |= EXT2_S_IWGRP;
  if (vnode->mode & VFS_S_IXGRP) inode.i_mode |= EXT2_S_IXGRP;
  if (vnode->mode & VFS_S_IROTH) inode.i_mode |= EXT2_S_IROTH;
  if (vnode->mode & VFS_S_IWOTH) inode.i_mode |= EXT2_S_IWOTH;
  if (vnode->mode & VFS_S_IXOTH) inode.i_mode |= EXT2_S_IXOTH;
  if (vnode->mode & VFS_S_ISUID) inode.i_mode |= EXT2_S_ISUID;
  if (vnode->mode & VFS_S_ISGID) inode.i_mode |= EXT2_S_ISGID;
  if (vnode->mode & VFS_S_ISVTX) inode.i_mode |= EXT2_S_ISVTX;

  inode.i_size = vnode->len;
  inode.i_uid = vnode->uid;
  inode.i_gid = vnode->gid;
  result = write_inode(fs, vnode->num, &inode);

  if (inode.i_links_count == 0) {
    result = free_inode(fs, vnode->num, &inode);
    return result;
  }

  return 0;
}

static int ext2_lookup(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(parent->fstype, "ext2") == 0);

  const ext2fs_t* fs = (const ext2fs_t*)parent->fs;
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

static int ext2_mknod(vnode_t* parent, const char* name,
                      vnode_type_t type, apos_dev_t dev) {
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

  uint16_t ext2_mode = 0;
  switch (type) {
    case VNODE_REGULAR: ext2_mode = EXT2_S_IFREG; break;
    case VNODE_BLOCKDEV: ext2_mode = EXT2_S_IFBLK; break;
    case VNODE_CHARDEV: ext2_mode = EXT2_S_IFCHR; break;
    case VNODE_FIFO: ext2_mode = EXT2_S_IFIFO; break;
    case VNODE_SOCKET: ext2_mode = EXT2_S_IFSOCK; break;
    case VNODE_UNINITIALIZED:
    case VNODE_INVALID:
    case VNODE_DIRECTORY:
    case VNODE_SYMLINK:
    case VNODE_MAX:
      die("invalid vnode type in ext2_mknod");
  }

  ext2_inode_t child_inode;
  const int child_inode_num =
      make_inode(fs, parent->num, ext2_mode, dev, &child_inode);
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
      make_inode(fs, parent->num, EXT2_S_IFDIR, kmakedev(0, 0), &child_inode);
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
  if (fs->read_only) return -EROFS;

  ext2_inode_t parent_inode;
  int result = get_inode(fs, parent->num, &parent_inode);
  if (result)
    return result;
  KASSERT((parent_inode.i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);

  // Get the child inode.
  const int child_inode_num = ext2_lookup(parent, name);
  if (child_inode_num < 0) return child_inode_num;

  ext2_inode_t child_inode;
  result = get_inode(fs, child_inode_num, &child_inode);
  if (result) return result;
  if ((child_inode.i_mode & EXT2_S_MASK) != EXT2_S_IFDIR)
    return -ENOTDIR;

  // Make sure it is empty.
  result = dirent_iterate(fs, &child_inode, 0, &ext2_rmdir_iter_func, 0x0);
  if (result)
    return -ENOTEMPTY;

  // Can't hard link directories, so should just be 2 links.
  KASSERT(child_inode.i_links_count == 2);

  // TODO(aoates): unlink_internal can block --- what happens if another thread
  // tries to simultaneously add a new entry to this directory?
  //
  // POSIX dictates that the '.' and '..' entries will be removed, but the
  // directory will exist until all outstanding references are closed, *and* no
  // new files can be created in the directory.

  result = unlink_internal(fs, &parent_inode, name);
  if (result)
    return result;

  // Update link counts.
  parent_inode.i_links_count--;
  write_inode(fs, parent->num, &parent_inode);

  // Unlink '.' and '..' entries.
  result = unlink_internal(fs, &child_inode, "..");
  if (result)
    return result;

  result = unlink_internal(fs, &child_inode, ".");
  if (result)
    return result;

  child_inode.i_links_count -= 2;
  write_inode(fs, child_inode_num, &child_inode);
  return 0;
}

static int ext2_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_REGULAR || vnode->type == VNODE_SYMLINK);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);
  KASSERT(offset >= 0);

  if (offset > vnode->len)
    return 0;

  const ext2fs_t* fs = (const ext2fs_t*)vnode->fs;
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
  KASSERT(vnode->len == (int)inode.i_size);
  const uint32_t block = get_inode_block(fs, &inode, inode_block);
  KASSERT(block > 0);

  const void* block_data = ext2_block_get(fs, block);
  if (!block_data) {
    return -ENOMEM;
  }
  KASSERT_DBG(block_offset + len <= ext2_block_size(fs));
  KASSERT_DBG(len <= bufsize);
  kmemcpy(buf, block_data + block_offset, len);

  ext2_block_put(fs, block, BC_FLUSH_NONE);
  return len;
}

static int ext2_write_inode(ext2fs_t* fs, int vnode_num, ext2_inode_t* inode,
                            int offset, const void* buf, int bufsize) {
  KASSERT((inode->i_mode & EXT2_S_MASK) == EXT2_S_IFREG ||
          (inode->i_mode & EXT2_S_MASK) == EXT2_S_IFLNK);
  KASSERT(offset >= 0);

  // Resize the file if needed.
  const uint32_t block_size = ext2_block_size(fs);
  if ((uint32_t)offset + bufsize > inode->i_size) {
    const uint32_t new_size = offset + bufsize;
    int result = resize_inode(fs, inode, vnode_num, new_size, 1);
    if (result) return result;
  }
  KASSERT((int)inode->i_size >= offset + bufsize);

  uint32_t bytes_to_write = bufsize;
  while (bytes_to_write > 0) {
    const uint32_t inode_block = offset / block_size;
    const uint32_t block_offset = offset % block_size;
    const uint32_t chunk_size = min(block_size - block_offset, bytes_to_write);

    const uint32_t block = get_inode_block(fs, inode, inode_block);
    KASSERT(block > 0);

    void* block_data = ext2_block_get(fs, block);
    if (!block_data) {
      return -ENOMEM;
    }
    KASSERT_DBG(block_offset + chunk_size <= block_size);
    kmemcpy(block_data + block_offset, buf, chunk_size);
    ext2_block_put(fs, block, BC_FLUSH_ASYNC);

    offset += chunk_size;
    buf += chunk_size;
    bytes_to_write -= chunk_size;
  }
  return bufsize;
}

static int ext2_write(vnode_t* vnode, int offset,
                      const void* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_REGULAR);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);
  KASSERT(offset >= 0);

  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  if (fs->read_only) {
    return -EROFS;
  }

  ext2_inode_t inode;
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }
  KASSERT(vnode->len == (int)inode.i_size);

  result = ext2_write_inode(fs, vnode->num, &inode, offset, buf, bufsize);
  vnode->len = inode.i_size;
  return result;
}

static int ext2_link(vnode_t* parent, vnode_t* vnode, const char* name) {
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

  // Link it into the directory.
  result = link_internal(fs, &parent_inode, parent->num, name, vnode->num);
  parent->len = parent_inode.i_size;

  if (result == 0) {
    ext2_inode_t child_inode;
    // TODO(aoates): do we want to store the inode in the vnode?
    result = get_inode(fs, vnode->num, &child_inode);
    if (result) {
      // TODO(aoates): roll back update.
      return result;
    }

    if (vnode->type == VNODE_DIRECTORY) {
      uint32_t orig_dotdot_ino = 0;
      result = relink_internal(fs, &child_inode, "..", parent->num,
                               &orig_dotdot_ino);
      if (result) return result;
      if (orig_dotdot_ino != (uint32_t)parent->num) {
        // Update link counts if necessary.
        ext2_inode_t orig_parent_inode;
        result = get_inode(fs, orig_dotdot_ino, &orig_parent_inode);
        if (result) return result;
        orig_parent_inode.i_links_count--;
        KASSERT_DBG(orig_parent_inode.i_links_count >= 2);
        result = write_inode(fs, orig_dotdot_ino, &orig_parent_inode);
        if (result) return result;

        parent_inode.i_links_count++;
        result = write_inode(fs, parent->num, &parent_inode);
        if (result) return result;
      }
    }
    child_inode.i_links_count++;
    result = write_inode(fs, vnode->num, &child_inode);
  }

  return result;
}

static int ext2_unlink(vnode_t* parent, const char* name) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(parent->fstype, "ext2") == 0);

  // Get the parent inode.
  ext2fs_t* fs = (ext2fs_t*)parent->fs;
  if (fs->read_only) return -EROFS;

  ext2_inode_t parent_inode;
  int result = get_inode(fs, parent->num, &parent_inode);
  if (result)
    return result;
  KASSERT((parent_inode.i_mode & EXT2_S_MASK) == EXT2_S_IFDIR);

  // Get the child inode.
  const int child_inode_num = ext2_lookup(parent, name);
  if (child_inode_num < 0)
    return child_inode_num;

  ext2_inode_t child_inode;
  result = get_inode(fs, child_inode_num, &child_inode);
  if (result)
    return result;

  KASSERT(child_inode.i_links_count >= 1);

  result = unlink_internal(fs, &parent_inode, name);
  if (result)
    return result;

  // Update link counts.
  child_inode.i_links_count--;
  write_inode(fs, child_inode_num, &child_inode);

  return 0;
}

typedef struct {
  void* buf;
  int bufsize;
  kdirent_t* last_dirent;  // The last dirent we put into the buffer.
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
    getdents_args->last_dirent->d_offset = offset;
  }

  const int dirent_out_size =
      sizeof(kdirent_t) + little_endian_dirent->name_len + 1;
  if (dirent_out_size > getdents_args->bufsize) {
    // Out of room, we're done.
    return 1;
  }

  kdirent_t* dirent_out = (kdirent_t*)getdents_args->buf;
  dirent_out->d_ino = ltoh32(little_endian_dirent->inode);
  dirent_out->d_offset = -1;  // We'll update this in the next iteration.
  dirent_out->d_reclen = dirent_out_size;
  kstrncpy(dirent_out->d_name, little_endian_dirent->name,
           little_endian_dirent->name_len);
  dirent_out->d_name[little_endian_dirent->name_len] = '\0';

  getdents_args->buf += dirent_out_size;
  getdents_args->bufsize -= dirent_out_size;
  getdents_args->last_dirent = dirent_out;
  return 0;
}

static int ext2_getdents(vnode_t* vnode, int offset, void* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_DIRECTORY);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);

  const ext2fs_t* fs = (const ext2fs_t*)vnode->fs;
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
      KASSERT(arg.last_dirent->d_offset >= offset);
    }
  } else if (arg.last_dirent != 0x0) {
    // If we went through all the dirents possible, set the offset to the end of
    // the file.
    KASSERT(arg.last_dirent->d_offset == -1);
    arg.last_dirent->d_offset = vnode->len;
  }
  return bufsize - arg.bufsize;
}

int ext2_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);

  const ext2fs_t* fs = (const ext2fs_t*)vnode->fs;
  ext2_inode_t inode;
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }

  stat_out->st_nlink = inode.i_links_count;
  stat_out->st_blksize = ext2_block_size(fs);
  stat_out->st_blocks = inode.i_blocks;

  return 0;
}

static int ext2_symlink(vnode_t* parent, const char* name, const char* path) {
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
      make_inode(fs, parent->num,
                 EXT2_S_IFLNK | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IXUSR |
                     EXT2_S_IRGRP | EXT2_S_IWGRP | EXT2_S_IXGRP | EXT2_S_IROTH |
                     EXT2_S_IWOTH | EXT2_S_IXOTH,
                 kmakedev(0, 0), &child_inode);
  if (child_inode_num < 0) {
    return child_inode_num;
  }

  // Write the path.
  const int path_len = kstrlen(path);
  if (path_len < EXT2_SYMLINK_INLINE_LEN) {
    kmemcpy(child_inode.i_block, path, path_len);
  } else {
    result =
        ext2_write_inode(fs, child_inode_num, &child_inode, 0, path, path_len);
    if (result < 0) {
      // TODO(aoates): free the allocated inode
      return result;
    }
  }
  child_inode.i_size = path_len;

  result = write_inode(fs, child_inode_num, &child_inode);
  if (result) {
    KLOG(WARNING, "Unable to writeback inode %d: %s\n",
         child_inode_num, errorname(-result));
    return result;
  }

  // Link it into the directory.
  result = link_internal(fs, &parent_inode, parent->num, name, child_inode_num);
  parent->len = parent_inode.i_size;
  if (result) {
    // TODO(aoates): free the allocated inode
    return result;
  }

  return 0;
}

static int ext2_readlink(vnode_t* vnode, char* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_SYMLINK);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);

  if (vnode->len < EXT2_SYMLINK_INLINE_LEN) {
    const ext2fs_t* fs = (const ext2fs_t*)vnode->fs;
    ext2_inode_t inode;
    // TODO(aoates): do we want to store the inode in the vnode?
    int result = get_inode(fs, vnode->num, &inode);
    if (result) return result;

    const int bytes_to_copy = min((int)inode.i_size, bufsize);
    kmemcpy(buf, inode.i_block, bytes_to_copy);

    return bytes_to_copy;
  } else {
    return ext2_read(vnode, 0, buf, bufsize);
  }
}

static int ext2_truncate(vnode_t* vnode, koff_t length) {
  KASSERT(vnode->type == VNODE_REGULAR);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);
  KASSERT(length >= 0);

  ext2fs_t* fs = (ext2fs_t*)vnode->fs;
  if (fs->read_only) {
    return -EROFS;
  }

  ext2_inode_t inode;
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }
  KASSERT(vnode->len == (int)inode.i_size);
  // TODO(aoates): check against max length [64-bit].

  result = resize_inode(fs, &inode, vnode->num, length, 1);
  vnode->len = inode.i_size;
  return result;
}

// Either read or write a page from the file.
static int ext2_page_op(vnode_t* vnode, int page_offset, void* buf, int is_write) {
  KASSERT(vnode->type == VNODE_REGULAR);
  KASSERT_DBG(kstrcmp(vnode->fstype, "ext2") == 0);
  KASSERT(page_offset >= 0);
  KASSERT(page_offset * PAGE_SIZE <= vnode->len);

  const ext2fs_t* fs = (const ext2fs_t*)vnode->fs;
  KASSERT(PAGE_SIZE % ext2_block_size(fs) == 0);
  const uint32_t inode_block = (page_offset * PAGE_SIZE) / ext2_block_size(fs);

  // How many bytes we'll actually read.
  const unsigned int len =
      min(PAGE_SIZE, vnode->len - (page_offset * PAGE_SIZE));
  KASSERT(len > 0);

  ext2_inode_t inode;
  int result = get_inode(fs, vnode->num, &inode);
  if (result) {
    return result;
  }
  KASSERT(vnode->len == (int)inode.i_size);

  // TODO(aoates): rewrite this to pull directly from the device instead of
  // caching the data twice.
  unsigned int bytes_left = len;
  for (unsigned int block_idx = 0;
       block_idx < ceiling_div(len, ext2_block_size(fs));
       ++block_idx) {
    KASSERT(bytes_left > 0);
    const uint32_t block = get_inode_block(fs, &inode, inode_block + block_idx);
    KASSERT(block > 0);

    void* block_data = ext2_block_get(fs, block);
    if (!block_data) {
      return -ENOMEM;
    }
    const unsigned int bytes_to_copy = min(bytes_left, ext2_block_size(fs));
    void* buf_offset = (char*)buf + (block_idx * ext2_block_size(fs));
    if (is_write) {
      kmemcpy(block_data, buf_offset, bytes_to_copy);
      ext2_block_put(fs, block, BC_FLUSH_ASYNC);
    } else {
      kmemcpy(buf_offset, block_data, bytes_to_copy);
      ext2_block_put(fs, block, BC_FLUSH_NONE);
    }

    bytes_left -= ext2_block_size(fs);
  }
  return 0;
}

static int ext2_read_page(vnode_t* vnode, int page_offset, void* buf) {
  return ext2_page_op(vnode, page_offset, buf, 0);
}

static int ext2_write_page(vnode_t* vnode, int page_offset, const void* buf) {
  return ext2_page_op(vnode, page_offset, (void*)buf, 1);
}
