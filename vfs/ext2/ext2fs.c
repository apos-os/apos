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

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/block_cache.h"
#include "kmalloc.h"
#include "vfs/ext2/ext2-internal.h"

int ext2_read_superblock(ext2fs_t* fs) {
  KASSERT(BLOCK_CACHE_BLOCK_SIZE >= 1024);
  const int sb_block_num = (BLOCK_CACHE_BLOCK_SIZE == 1024) ? 1 : 0;
  const int sb_block_offset = (BLOCK_CACHE_BLOCK_SIZE == 1024) ? 0 : 1024;
  void* sb_block = block_cache_get(fs->dev, sb_block_num);
  if (!sb_block) {
    return -ENOMEM;
  }

  kmemcpy(&fs->sb, sb_block + sb_block_offset, sizeof(ext2_superblock_t));
  ext2_superblock_ltoh(&fs->sb);
  block_cache_put(fs->dev, sb_block_num);

  // Check magic number and version.
  if (fs->sb.s_magic != EXT2_SUPER_MAGIC) {
    klogf("ext2: invalid magic number: %x\n", fs->sb.s_magic);
    return -EINVAL;
  }

  klogf("ext2 superblock found on dev %d.%d:\n", fs->dev.major, fs->dev.minor);
  ext2_superblock_log(&fs->sb);

  if (fs->sb.s_rev_level != EXT2_DYNAMIC_REV) {
    klogf("ext2: unsupported ext2 version: %d\n", fs->sb.s_rev_level);
    return -EINVAL;
  }
  if (fs->sb.s_state != EXT2_VALID_FS) {
    klogf("ext2: ext2 filesystem in bad state\n");
    return -EINVAL;
  }

  // Check incompatible features.
  if (fs->sb.s_feature_incompat != 0x0) {
    klogf("ext2: unsupported features: 0x%x\n", fs->sb.s_feature_incompat);
    return -EINVAL;
  }

  // Check RO features.
  if (fs->sb.s_feature_ro_compat != 0x0) {
    klogf("ext2: warning: unsupported RO features: 0x%x\n",
          fs->sb.s_feature_ro_compat);
    fs->read_only = 1;
  }

  // Check block size.
  if (fs->sb.s_log_block_size != 0 || fs->sb.s_log_frag_size != 0) {
    klogf("ext2: unsupported block or fragment size\n");
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
    void* bg_block = block_cache_get(fs->dev, block);
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
    block_cache_put(fs->dev, block);
  }

  for (unsigned int i = 0; i < fs->num_block_groups; ++i) {
    klogf("block group %d:\n", i);
    ext2_block_group_desc_log(&fs->block_groups[i]);
    klogf("\n");
  }

  return 0;
}

int ext2_flush_superblock(const ext2fs_t* fs) {
  KASSERT(BLOCK_CACHE_BLOCK_SIZE == ext2_block_size(fs));

  // Write out the superblock to every copy.
  for (uint32_t i = 0; i < fs->num_block_groups; ++i) {
    // TODO(aoates): handle sparse super block feature.
    const int sb_block_num = fs->sb.s_first_data_block + (i * fs->sb.s_blocks_per_group);
    const int sb_block_offset =
        ((i == 0 && ext2_block_size(fs) > 1024) ? 1024 : 0);
    KASSERT_DBG(sb_block_offset + sizeof(ext2_superblock_t) <= ext2_block_size(fs));

    void* sb_block = block_cache_get(fs->dev, sb_block_num);
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
    block_cache_put(fs->dev, sb_block_num);
  }

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
  for (uint32_t i = 0; i < fs->num_block_groups; ++i) {
    // TODO(aoates): handle sparse super block feature.
    // Get the first block of the block group, then the appropriate block within
    // that copy of the block descriptor table.
    const uint32_t bgdt_first_block =
        fs->sb.s_first_data_block + (i * fs->sb.s_blocks_per_group) + 1;
    const uint32_t bgdt_block_num = bgdt_first_block + flush_bg_bgdt_block_idx;
    ext2_block_group_desc_t* bgdt_block = block_cache_get(fs->dev, bgdt_block_num);
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
    block_cache_put(fs->dev, bgdt_block_num);
  }
  return 0;
}
