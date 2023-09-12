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
#include "user/include/apos/posix_signal.h"
#include "user/include/apos/resource.h"
#include "user/include/apos/termios.h"
#include "user/include/apos/vfs/dirent.h"
#include "user/include/apos/vfs/poll.h"
#include "user/include/apos/vfs/stat.h"

// stat() wrappers.
struct apos_timespec_32 {
  int32_t tv_sec;
  int32_t tv_nsec;
};
_Static_assert(sizeof(struct apos_timespec_32) == 8,
               "struct timespec wrong size!");

typedef struct {
  apos_dev_t st_dev;
  /* apos_ino_t */ int32_t st_ino;
  apos_mode_t st_mode;
  apos_nlink_t st_nlink;
  apos_uid_t st_uid;
  apos_gid_t st_gid;
  apos_dev_t st_rdev;
  /* apos_off_t */ int32_t st_size;
  struct apos_timespec_32 st_atim;
  struct apos_timespec_32 st_mtim;
  struct apos_timespec_32 st_ctim;
  apos_blksize_t st_blksize;
  apos_blkcnt_t st_blocks;
} apos_stat_32_t;
_Static_assert(sizeof(apos_stat_32_t) == 64, "apos_stat_32_t wrong size!");

#if ARCH == ARCH_i586
_Static_assert(sizeof(struct apos_timespec_32) == sizeof(struct apos_timespec),
               "struct apos_timespec_32 wrong size!");
_Static_assert(sizeof(apos_stat_32_t) == sizeof(apos_stat_t),
               "apos_stat_32_t wrong size!");
#endif

int vfs_stat_32(const char* path, apos_stat_32_t* stat);
int vfs_lstat_32(const char* path, apos_stat_32_t* stat);
int vfs_fstat_32(int fd, apos_stat_32_t* stat);

// Signal handling wrappers.
struct ksigaction_32 {
  /* sighandler_t */ uint32_t sa_handler;
  ksigset_t sa_mask;
  int sa_flags;
};
_Static_assert(sizeof(struct ksigaction_32) == 12,
               "ksigaction_32_t wrong size!");
#if ARCH == ARCH_i586
_Static_assert(sizeof(struct ksigaction_32) == sizeof(struct ksigaction),
               "struct ksigaction_32 wrong size!");
#endif

int proc_sigaction_32(int signum, const struct ksigaction_32* act,
                      struct ksigaction_32* oldact);

// getdents wrappers.
typedef struct {
  /* apos_ino_t */ int32_t d_ino;
  /* apos_off_t */ int32_t d_offset;
  /* size_t */ uint32_t d_reclen;
  char d_name[];  // Null-terminated filename
} kdirent_32_t;
_Static_assert(sizeof(kdirent_32_t) == 12, "kdirent_32_t wrong size!");
#if ARCH == ARCH_i586
_Static_assert(sizeof(kdirent_32_t) == sizeof(kdirent_t),
               "kdirent_32_t wrong size!");
#endif

int vfs_getdents_32(int fd, kdirent_32_t* buf, int count);

// rlimit wrappers.
struct apos_rlimit_32 {
  /* rlim_t */ uint32_t rlim_cur;  // The current (soft) limit.
  /* rlim_t */ uint32_t rlim_max;  // The hard limit.
};
_Static_assert(sizeof(struct apos_rlimit_32) == 8,
               "struct rlimit_32 wrong size!");
#if ARCH == ARCH_i586
_Static_assert(sizeof(struct apos_rlimit_32) == sizeof(struct apos_rlimit),
               "struct rlimit_32 wrong size!");
#endif
int proc_getrlimit_32(int resource, struct apos_rlimit_32* lim);
int proc_setrlimit_32(int resource, const struct apos_rlimit_32* lim);

int mmap_wrapper_32(void* addr_inout, size_t length, int prot, int flags,
                    int fd, apos_off_t offset);

int futex_op_32(uint32_t* uaddr, int futex_op, uint32_t val,
                const struct apos_timespec_32* timeout, uint32_t* uaddr2,
                uint32_t val3);

// Some types we want to ensure are always the same size on all architectures.
_Static_assert(sizeof(struct ktermios) == 28, "struct ktermios wrong size!");
_Static_assert(sizeof(struct apos_pollfd) == 8, "struct pollfd wrong size!");

int apos_get_timespec_32(struct apos_timespec_32* ts);

#endif
