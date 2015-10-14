// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

// Structs and wrappers for syscalls from 32-bit programs into a 64-bit kernel.
#ifndef APOO_SYSCALL_WRAPPERS32_H
#define APOO_SYSCALL_WRAPPERS32_H

#include "common/config.h"
#include "common/types.h"
#include "user/include/apos/vfs/stat.h"

struct timespec_32 {
  int32_t tv_sec;
  int32_t tv_nsec;
};
_Static_assert(sizeof(struct timespec_32) == 8, "struct timespec wrong size!");

typedef struct {
  apos_dev_t st_dev;         // Device containing the file.
  /* ino_t */ int32_t st_ino;              // Inode number.
  mode_t st_mode;            // File type and mode.
  nlink_t st_nlink;          // Number of hard links.
  uid_t st_uid;              // File owner.
  gid_t st_gid;              // File group.
  apos_dev_t st_rdev;        // Device ID (if special file).
  /* off_t */ int32_t st_size;             // Size, in bytes.
  struct timespec_32 st_atim;   // Last data access timestamp.
  struct timespec_32 st_mtim;   // Last data modification timestamp.
  struct timespec_32 st_ctim;   // Last file status change timestamp.
  blksize_t st_blksize;      // File system block size.
  blkcnt_t st_blocks;        // Number of 512B blocks allocated.
} apos_stat_32_t;
_Static_assert(sizeof(apos_stat_32_t) == 64, "apos_stat_32_t wrong size!");

#if ARCH == ARCH_i586
_Static_assert(sizeof(struct timespec_32) == sizeof(struct timespec),
               "struct timespec_32 wrong size!");
_Static_assert(sizeof(apos_stat_32_t) == sizeof(apos_stat_t),
               "apos_stat_32_t wrong size!");
#endif

int vfs_stat_32(const char* path, apos_stat_32_t* stat);
int vfs_lstat_32(const char* path, apos_stat_32_t* stat);
int vfs_fstat_32(int fd, apos_stat_32_t* stat);

int mmap_wrapper_32(void* addr_inout, addr_t length, int prot, int flags,
                    int fd, addr_t offset);

#endif
