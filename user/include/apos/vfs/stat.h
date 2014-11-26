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
#  include "user/include/apos/dev.h"
#  include "user/include/apos/posix_types.h"
#else
#  include <apos/dev.h>
#  include <apos/posix_types.h>
#endif

// File type flags for mode_t.
#define VFS_S_IFREG     0100000
#define VFS_S_IFCHR     020000
#define VFS_S_IFBLK     060000
#define VFS_S_IFDIR     040000
#define VFS_S_IFLNK     0120000
#define VFS_S_IFIFO     010000
#define VFS_S_IFSOCK    0140000
#define VFS_S_IFMT      (VFS_S_IFREG | VFS_S_IFCHR | VFS_S_IFBLK | \
                         VFS_S_IFDIR | VFS_S_IFLNK | VFS_S_IFIFO | VFS_S_IFSOCK)

// Mode flags for mode_t.
#define VFS_S_IRWXU     0700
#define VFS_S_IRUSR     0400
#define VFS_S_IWUSR     0200
#define VFS_S_IXUSR     0100

#define VFS_S_IRWXG     070
#define VFS_S_IRGRP     040
#define VFS_S_IWGRP     020
#define VFS_S_IXGRP     010

#define VFS_S_IRWXO     07
#define VFS_S_IROTH     04
#define VFS_S_IWOTH     02
#define VFS_S_IXOTH     01

// TODO(aoates): implement these.
#define VFS_S_ISUID     04000
#define VFS_S_ISGID     02000
#define VFS_S_ISVTX     01000

#define VFS_S_ISREG(m)  (((m) & VFS_S_IFMT) == VFS_S_IFREG)
#define VFS_S_ISCHR(m)  (((m) & VFS_S_IFMT) == VFS_S_IFCHR)
#define VFS_S_ISBLK(m)  (((m) & VFS_S_IFMT) == VFS_S_IFBLK)
#define VFS_S_ISDIR(m)  (((m) & VFS_S_IFMT) == VFS_S_IFDIR)
#define VFS_S_ISLNK(m)  (((m) & VFS_S_IFMT) == VFS_S_IFLNK)
#define VFS_S_ISFIFO(m) (((m) & VFS_S_IFMT) == VFS_S_IFIFO)
#define VFS_S_ISSOCK(m) (((m) & VFS_S_IFMT) == VFS_S_IFSOCK)

// Information about a vnode.
struct stat {
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
};
// TODO(aoates): replace all instances of apos_stat_t with stat_t.
typedef struct stat apos_stat_t;

#endif
