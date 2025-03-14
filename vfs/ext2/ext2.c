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
#include "dev/block_dev.h"
#include "dev/dev.h"
#include "memory/kmalloc.h"
#include "vfs/ext2/ext2-internal.h"
#include "vfs/ext2/ext2_ops.h"
#include "vfs/ext2/ext2fs.h"
#include "vfs/fs.h"
#include "vfs/vfs.h"

fs_t* ext2_create_fs(void) {
  ext2fs_t* fs = kmalloc(sizeof(ext2fs_t));
  kmemset(fs, 0, sizeof(ext2fs_t));
  vfs_fs_init(&fs->fs);

  fs->mounted = 0;
  fs->unhealthy = 0;
  kmutex_init(&fs->mu);
  return (fs_t*)fs;
}

void ext2_destroy_fs(fs_t* fs) {
  ext2fs_t* ext2fs = (ext2fs_t*)fs;
  KASSERT(!ext2fs->mounted);
  if (ext2fs->block_groups) {
    kfree(ext2fs->block_groups);
  }
  kfree(ext2fs);
}

int ext2_mount(fs_t* fs, apos_dev_t dev) {
  ext2fs_t* ext2fs = (ext2fs_t*)fs;
  if (ext2fs->mounted) {
    return -EINVAL;
  }

  ext2fs->fs.dev = dev;
  ext2fs->obj = dev_get_block_memobj(dev);
  int result = ext2_read_superblock(ext2fs);
  if (result) {
    return result;
  }

  result = ext2_read_block_groups(ext2fs);
  if (result) {
    return result;
  }

  ext2_set_ops(fs);
  kstrcpy(fs->fstype, "ext2");

  // TODO
  ext2fs->mounted = 1;
  return 0;
}

int ext2_create_path(const char* source, unsigned long flags, const void* data,
                     size_t data_len, fs_t** fs_out) {
  apos_stat_t stat;
  int result = vfs_stat(source, &stat);
  if (result) return result;

  if (!VFS_S_ISBLK(stat.st_mode)) {
    return -ENOTSUP;
  }

  *fs_out = ext2_create_fs();
  result = ext2_mount(*fs_out, stat.st_rdev);
  if (result) {
    ext2_destroy_fs(*fs_out);
    return result;
  }

  return 0;
}
