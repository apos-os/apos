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

#include "vfs/vfs.h"

#include "vfs/ext2/ext2-internal.h"

// An ext2 fs structure.
typedef struct {
  fs_t fs;  // Embedded fs interface.

  dev_t dev;
  int mounted;
  int read_only;

  // In-memory copy of the superblock.  Only valid if mounted == true.
  ext2_superblock_t sb;
} ext2fs_t;

#endif
