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

#include "vfs/ext2/ext2fs.h"

#include "arch/common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/block_cache.h"
#include "memory/kmalloc.h"
#include "vfs/ext2/ext2-internal.h"

#define KLOG(...) klogfm(KL_EXT2, __VA_ARGS__)

#define SUPPORTED_RO_FEATURES EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER

void* ext2_block_get(const ext2fs_t* fs, int offset) {
  const uint32_t block_size = ext2_block_size(fs);
  KASSERT_DBG(fs->sb.s_magic == EXT2_SUPER_MAGIC);
  KASSERT_DBG(BLOCK_CACHE_BLOCK_SIZE >= block_size);
  KASSERT_DBG(BLOCK_CACHE_BLOCK_SIZE % block_size == 0);

  const int fs_blocks_per_dev_block = BLOCK_CACHE_BLOCK_SIZE / block_size;
  const int dev_block = offset / fs_blocks_per_dev_block;
  const int dev_block_offset = offset % fs_blocks_per_dev_block;
  bc_entry_t* dev_block_entry = 0x0;
  const int result = block_cache_get(fs->obj, dev_block, &dev_block_entry);
  if (result == 0) {
    return dev_block_entry->block + dev_block_offset * block_size;
  } else {
    return 0x0;
  }
}

void ext2_block_put(const ext2fs_t* fs, int offset, block_cache_flush_t flush_mode) {
  const uint32_t block_size = ext2_block_size(fs);
  KASSERT_DBG(BLOCK_CACHE_BLOCK_SIZE >= block_size);
  KASSERT_DBG(BLOCK_CACHE_BLOCK_SIZE % block_size == 0);

  const int fs_blocks_per_dev_block = BLOCK_CACHE_BLOCK_SIZE / block_size;
  const int dev_block = offset / fs_blocks_per_dev_block;

  // Get the block, then put it twice, once for this new reference and once for
  // the one outstanding.
  bc_entry_t* dev_block_entry = 0x0;
  const int result = block_cache_get(fs->obj, dev_block, &dev_block_entry);
  KASSERT(result == 0);
  block_cache_put(dev_block_entry, BC_FLUSH_NONE);
  block_cache_put(dev_block_entry, flush_mode);
}

int ext2_read_superblock(ext2fs_t* fs) {
  KASSERT(BLOCK_CACHE_BLOCK_SIZE >= 1024);
  const int sb_block_num = (BLOCK_CACHE_BLOCK_SIZE == 1024) ? 1 : 0;
  const int sb_block_offset = (BLOCK_CACHE_BLOCK_SIZE == 1024) ? 0 : 1024;
  bc_entry_t* sb_block = 0x0;
  if (block_cache_get(fs->obj, sb_block_num, &sb_block) != 0) {
    return -ENOMEM;
  }

  kmemcpy(&fs->sb, sb_block->block + sb_block_offset, sizeof(ext2_superblock_t));
  ext2_superblock_ltoh(&fs->sb);
  block_cache_put(sb_block, BC_FLUSH_NONE);

  // Check magic number and version.
  if (fs->sb.s_magic != EXT2_SUPER_MAGIC) {
    KLOG(INFO, "ext2: invalid magic number: %x\n", fs->sb.s_magic);
    return -EINVAL;
  }

  KLOG(INFO, "ext2 superblock found on dev %d.%d:\n",
       kmajor(fs->fs.dev), kminor(fs->fs.dev));
  ext2_superblock_log(INFO, &fs->sb);

  if (fs->sb.s_rev_level != EXT2_DYNAMIC_REV) {
    KLOG(INFO, "ext2: unsupported ext2 version: %d\n", fs->sb.s_rev_level);
    return -EINVAL;
  }
  if (fs->sb.s_state != EXT2_VALID_FS) {
    KLOG(INFO, "ext2: ext2 filesystem in bad state\n");
    return -EINVAL;
  }

  // Check incompatible features.
  if (fs->sb.s_feature_incompat != 0x0) {
    KLOG(INFO, "ext2: unsupported features: 0x%x\n", fs->sb.s_feature_incompat);
    return -EINVAL;
  }

  // Check RO features.
  if (fs->sb.s_feature_ro_compat & ~SUPPORTED_RO_FEATURES) {
    KLOG(INFO, "ext2: warning: unsupported RO features: 0x%x\n",
         fs->sb.s_feature_ro_compat);
    fs->read_only = 1;
  }

  // Check block size.
  const uint32_t block_size = ext2_block_size(fs);
  if (block_size > BLOCK_CACHE_BLOCK_SIZE ||
      fs->sb.s_log_frag_size != fs->sb.s_log_block_size) {
    KLOG(INFO, "ext2: unsupported block or fragment size\n");
    return -EINVAL;
  }

  return 0;
}

int ext2_read_block_groups(ext2fs_t* fs) {
  const uint32_t block_size = ext2_block_size(fs);
  const int bg_first_block = fs->sb.s_first_data_block + 1;
  fs->num_block_groups =
      ceiling_div(fs->sb.s_blocks_count, fs->sb.s_blocks_per_group);

  fs->block_groups = (ext2_block_group_desc_t*)kmalloc(
      sizeof(ext2_block_group_desc_t) * fs->num_block_groups);

  // How many blocks are in the block group descriptor table.
  const int bgdt_blocks =
      ceiling_div(fs->num_block_groups * sizeof(ext2_block_group_desc_t),
                  block_size);
  uint32_t bgs_remaining = fs->num_block_groups;
  for (int i = 0; i < bgdt_blocks; ++i) {
    const int block = bg_first_block + i;
    void* bg_block = ext2_block_get(fs, block);
    if (!bg_block) {
      kfree(fs->block_groups);
      fs->block_groups = 0x0;
      return -ENOMEM;
    }

    const uint32_t bgs_in_this_block =
        min(fs->sb.s_blocks_per_group, bgs_remaining);
    for (uint32_t bufidx = 0; bufidx < bgs_in_this_block; ++bufidx) {
      ext2_block_group_desc_t* cbg =
          &fs->block_groups[fs->num_block_groups - bgs_remaining];
      kmemcpy(cbg, bg_block + (bufidx * sizeof(ext2_block_group_desc_t)),
              sizeof(ext2_block_group_desc_t));
      ext2_block_group_desc_ltoh(cbg);
      bgs_remaining--;
    }
    ext2_block_put(fs, block, BC_FLUSH_NONE);
  }

  for (unsigned int i = 0; i < fs->num_block_groups; ++i) {
    KLOG(INFO, "block group %d:\n", i);
    ext2_block_group_desc_log(INFO, &fs->block_groups[i]);
    KLOG(INFO, "\n");
  }

  return 0;
}

static int flush_superblock_in_bg(const ext2fs_t* fs, unsigned int bg) {
  const int sb_block_num = fs->sb.s_first_data_block + (bg * fs->sb.s_blocks_per_group);
  const int sb_block_offset =
      ((bg == 0 && ext2_block_size(fs) > 1024) ? 1024 : 0);
  KASSERT_DBG(sb_block_offset + sizeof(ext2_superblock_t) <= ext2_block_size(fs));

  void* sb_block = ext2_block_get(fs, sb_block_num);
  if (!sb_block) {
    // Yikes! Only partially flushed!
    return -ENOMEM;
  }

  // TODO(aoates): is it really safe to write it to the disk, *then* endian-swap
  // it?  OTOH, it seems silly to copy it to an intermediate buffer, then fix
  // endianess, then copy again.
  ext2_superblock_t* on_disk_sb = (ext2_superblock_t*)(sb_block + sb_block_offset);
  KASSERT(on_disk_sb->s_magic == htol16(EXT2_SUPER_MAGIC));

  kmemcpy(on_disk_sb, &fs->sb, sizeof(ext2_superblock_t));
  ext2_superblock_ltoh(on_disk_sb);
  ext2_block_put(fs, sb_block_num, BC_FLUSH_ASYNC);
  return 0;
}

int ext2_flush_superblock(const ext2fs_t* fs) {
  // Write out the superblock to every copy.
  if (fs->sb.s_feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER) {
    flush_superblock_in_bg(fs, 0);
    if (fs->num_block_groups > 1) flush_superblock_in_bg(fs, 1);
    for (uint32_t i = 3; i < fs->num_block_groups; i *= 3)
      flush_superblock_in_bg(fs, i);
    for (uint32_t i = 5; i < fs->num_block_groups; i *= 5)
      flush_superblock_in_bg(fs, i);
    for (uint32_t i = 7; i < fs->num_block_groups; i *= 7)
      flush_superblock_in_bg(fs, i);
  } else {
    for (uint32_t i = 0; i < fs->num_block_groups; ++i) {
      int result = flush_superblock_in_bg(fs, i);
      if (result) {
        return result;
      }
    }
  }

  return 0;
}

// Flush the copy of the given bgd stored in the given block group.
static int flush_bgdt_in_bg(const ext2fs_t* fs,
                            const ext2_block_group_desc_t* bgd_to_flush,
                            unsigned int bg,
                            uint32_t flush_bg_bgdt_block_idx,
                            uint32_t flush_bg_bgdt_idx_in_block) {
  // Get the first block of the block group, then the appropriate block within
  // that copy of the block descriptor table.
  const uint32_t bgdt_first_block =
      fs->sb.s_first_data_block + (bg * fs->sb.s_blocks_per_group) + 1;
  const uint32_t bgdt_block_num = bgdt_first_block + flush_bg_bgdt_block_idx;
  ext2_block_group_desc_t* bgdt_block = ext2_block_get(fs, bgdt_block_num);
  if (!bgdt_block) {
    // Yikes! Only partially flushed!
    return -ENOMEM;
  }

  ext2_block_group_desc_t* on_disk_bgd = &bgdt_block[flush_bg_bgdt_idx_in_block];

  // Sanity check the on-disk bgd to make sure we didn't pick the wrong block.
  KASSERT(on_disk_bgd->bg_block_bitmap == htol32(bgd_to_flush->bg_block_bitmap));
  KASSERT(on_disk_bgd->bg_inode_bitmap == htol32(bgd_to_flush->bg_inode_bitmap));
  KASSERT(on_disk_bgd->bg_inode_table == htol32(bgd_to_flush->bg_inode_table));

  kmemcpy(on_disk_bgd, bgd_to_flush, sizeof(ext2_block_group_desc_t));
  ext2_block_group_desc_ltoh(on_disk_bgd);
  ext2_block_put(fs, bgdt_block_num, BC_FLUSH_ASYNC);
  return 0;
}

int ext2_flush_block_group(const ext2fs_t* fs, unsigned int bg) {
  KASSERT(bg < fs->num_block_groups);

  const uint32_t block_size = ext2_block_size(fs);
  const int bg_descs_per_block = block_size / sizeof(ext2_block_group_desc_t);

  // Where in the bgdt the chosen bg descriptor is (both block index, and
  // descriptor offset within that block).
  const uint32_t flush_bg_bgdt_block_idx = bg / bg_descs_per_block;
  const uint32_t flush_bg_bgdt_idx_in_block = bg % bg_descs_per_block;
  const ext2_block_group_desc_t* bgd_to_flush = &fs->block_groups[bg];

  // Flush for each copy of the bgdt.
  if (fs->sb.s_feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER) {
    const uint32_t fl_block = flush_bg_bgdt_block_idx;
    const uint32_t fl_idx = flush_bg_bgdt_idx_in_block;

    flush_bgdt_in_bg(fs, bgd_to_flush, 0, fl_block, fl_idx);
    if (fs->num_block_groups > 1)
      flush_bgdt_in_bg(fs, bgd_to_flush, 1, fl_block, fl_idx);
    for (uint32_t i = 3; i < fs->num_block_groups; i *= 3)
      flush_bgdt_in_bg(fs, bgd_to_flush, i, fl_block, fl_idx);
    for (uint32_t i = 5; i < fs->num_block_groups; i *= 5)
      flush_bgdt_in_bg(fs, bgd_to_flush, i, fl_block, fl_idx);
    for (uint32_t i = 7; i < fs->num_block_groups; i *= 7)
      flush_bgdt_in_bg(fs, bgd_to_flush, i, fl_block, fl_idx);
  } else {
    for (uint32_t i = 0; i < fs->num_block_groups; ++i) {
      int result = flush_bgdt_in_bg(
          fs, bgd_to_flush, i,
          flush_bg_bgdt_block_idx, flush_bg_bgdt_idx_in_block);
      if (result) {
        return result;
      }
    }
  }
  return 0;
}
