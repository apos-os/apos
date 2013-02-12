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

#include "vfs/ext2/ext2.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/block_cache.h"
#include "kmalloc.h"
#include "vfs/ext2/ext2-internal.h"
#include "vfs/ext2/ext2fs.h"
#include "vfs/vfs.h"

static int ext2_read_superblock(ext2fs_t* fs) {
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

  return 0;
}

fs_t* ext2_create_fs() {
  ext2fs_t* fs = kmalloc(sizeof(ext2fs_t));
  kmemset(fs, 0, sizeof(ext2fs_t));

  fs->mounted = 0;
  return (fs_t*)fs;
}

void ext2_destroy_fs(fs_t* fs) {
  ext2fs_t* ext2fs = (ext2fs_t*)fs;
  KASSERT(!ext2fs->mounted);
  kfree(ext2fs);
}

int ext2_mount(fs_t* fs, dev_t dev) {
  ext2fs_t* ext2fs = (ext2fs_t*)fs;
  if (ext2fs->mounted) {
    return -EINVAL;
  }

  ext2fs->dev = dev;
  int result = ext2_read_superblock(ext2fs);
  if (result) {
    return result;
  }

  // TODO
  ext2fs->mounted = 1;
  return 0;
}
