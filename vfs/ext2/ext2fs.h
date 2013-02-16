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

#include "dev/dev.h"
#include "vfs/vfs.h"

#include "vfs/ext2/ext2-internal.h"

// An ext2 fs structure.
typedef struct {
  fs_t fs;  // Embedded fs interface.

  dev_t dev;
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
} ext2fs_t;

// Returns the block size in bytes.
static inline uint32_t ext2_block_size(ext2fs_t* fs) {
  return 1024 << fs->sb.s_log_block_size;
}

#endif
