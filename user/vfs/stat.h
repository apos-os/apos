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

#if __APOS_BUILDING_IN_TREE__
#  include "user/dev.h"
#  include "user/posix_types.h"
#else
#  include <apos/dev.h>
#  include <apos/posix_types.h>
#endif

typedef uint32_t mode_t;

// File type flags for mode_t.
#define VFS_S_IFMT      0xFF0000
#define VFS_S_IFREG     0x010000
#define VFS_S_IFCHR     0x020000
#define VFS_S_IFBLK     0x040000
#define VFS_S_IFDIR     0x080000
#define VFS_S_IFLNK     0x100000

// Mode flags for mode_t.
#define VFS_S_IRWXU     0x000700
#define VFS_S_IRUSR     0x000400
#define VFS_S_IWUSR     0x000200
#define VFS_S_IXUSR     0x000100

#define VFS_S_IRWXG     0x000070
#define VFS_S_IRGRP     0x000040
#define VFS_S_IWGRP     0x000020
#define VFS_S_IXGRP     0x000010

#define VFS_S_IRWXO     0x000007
#define VFS_S_IROTH     0x000004
#define VFS_S_IWOTH     0x000002
#define VFS_S_IXOTH     0x000001

// TODO(aoates): implement these.
#define VFS_S_ISUID     0x004000
#define VFS_S_ISGID     0x002000
#define VFS_S_ISVTX     0x001000

// Information about a vnode.
typedef struct {
  apos_dev_t st_dev;    // Device containing the file.
  ino_t st_ino;         // Inode number.
  mode_t st_mode;       // File type and mode.
  nlink_t st_nlink;     // Number of hard links.
  uid_t st_uid;         // File owner.
  gid_t st_gid;         // File group.
  apos_dev_t st_rdev;   // Device ID (if special file).
  off_t st_size;        // Size, in bytes.
  blksize_t st_blksize; // File system block size.
  blkcnt_t st_blocks;   // Number of 512B blocks allocated.
} apos_stat_t;

#endif
