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

#ifndef APOO_VFS_STAT_H
#define APOO_VFS_STAT_H

#include "common/posix_types.h"
#include "dev/dev.h"

// Information about a vnode.
// TODO(aoates): add ino_t and off_t typedefs
typedef struct {
  apos_dev_t st_dev;    // Device containing the file.
  int st_ino;           // Inode number.
  uint32_t st_mode;     // File type and mode.
  int st_nlink;         // Number of hard links.
  apos_dev_t st_rdev;   // Device ID (if special file).
  int st_size;          // Size, in bytes.
  blksize_t st_blksize; // File system block size.
  blkcnt_t st_blocks;   // Number of 512B blocks allocated.
} apos_stat_t;

#endif
