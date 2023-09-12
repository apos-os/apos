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

#include <stddef.h>
#include <stdint.h>

#include "common/kassert.h"
#include "common/kstring.h"
#include "common/time.h"
#include "memory/kmalloc.h"
#include "memory/mmap.h"
#include "proc/futex.h"
#include "proc/limit.h"
#include "proc/signal/signal.h"
#include "syscall/wrappers32.h"
#include "vfs/vfs.h"

static struct apos_timespec_32 timespec64to32(struct apos_timespec ts64) {
  struct apos_timespec_32 ts32;
  ts32.tv_sec = ts64.tv_sec;
  ts32.tv_nsec = ts64.tv_nsec;
  return ts32;
}

static struct apos_timespec timespec32to64(struct apos_timespec_32 ts32) {
  struct apos_timespec ts64;
  ts64.tv_sec = ts32.tv_sec;
  ts64.tv_nsec = ts32.tv_nsec;
  return ts64;
}

static void stat64to32(const apos_stat_t* stat64, apos_stat_32_t* stat32) {
  _Static_assert(sizeof(apos_stat_32_t) == 64, "Need to update stat64to32.");
  stat32->st_dev = stat64->st_dev;
  stat32->st_ino = stat64->st_ino;
  stat32->st_mode = stat64->st_mode;
  stat32->st_nlink = stat64->st_nlink;
  stat32->st_uid = stat64->st_uid;
  stat32->st_gid = stat64->st_gid;
  stat32->st_rdev = stat64->st_rdev;
  stat32->st_size = stat64->st_size;
  stat32->st_atim = timespec64to32(stat64->st_atim);
  stat32->st_mtim = timespec64to32(stat64->st_mtim);
  stat32->st_ctim = timespec64to32(stat64->st_ctim);
  stat32->st_blksize = stat64->st_blksize;
  stat32->st_blocks = stat64->st_blocks;
}

int vfs_stat_32(const char* path, apos_stat_32_t* stat) {
  apos_stat_t stat64;
  int result = vfs_stat(path, &stat64);
  stat64to32(&stat64, stat);
  return result;
}

int vfs_lstat_32(const char* path, apos_stat_32_t* stat) {
  apos_stat_t stat64;
  int result = vfs_lstat(path, &stat64);
  stat64to32(&stat64, stat);
  return result;
}

int vfs_fstat_32(int fd, apos_stat_32_t* stat) {
  apos_stat_t stat64;
  int result = vfs_fstat(fd, &stat64);
  stat64to32(&stat64, stat);
  return result;
}

static void sigaction32to64(const struct ksigaction_32* sa32,
                            struct ksigaction* sa64) {
  _Static_assert(sizeof(struct ksigaction_32) == 12,
                 "sigaction32to64 needs to be updated");
  sa64->sa_handler = (ksighandler_t)(intptr_t)sa32->sa_handler;
  sa64->sa_mask = sa32->sa_mask;
  sa64->sa_flags = sa32->sa_flags;
}

static void sigaction64to32(const struct ksigaction* sa64,
                            struct ksigaction_32* sa32) {
  _Static_assert(sizeof(struct ksigaction_32) == 12,
                 "sigaction64to32 needs to be updated");
  // TODO(aoates): test signal handling after a 64-to-32-bit exec().
  KASSERT_DBG(((addr_t)sa64->sa_handler & 0xFFFFFFFF00000000) == 0);
  sa32->sa_handler = (uint32_t)(addr_t)sa64->sa_handler;
  sa32->sa_mask = sa64->sa_mask;
  sa32->sa_flags = sa64->sa_flags;
}

int proc_sigaction_32(int signum, const struct ksigaction_32* act32,
                      struct ksigaction_32* oldact32) {
  struct ksigaction act, oldact;
  if (act32) sigaction32to64(act32, &act);
  int result =
      proc_sigaction(signum, act32 ? &act : NULL, oldact32 ? &oldact : NULL);
  if (oldact32) sigaction64to32(&oldact, oldact32);
  return result;
}

int vfs_getdents_32(int fd, kdirent_32_t* buf_in, int count) {
  _Static_assert(sizeof(kdirent_32_t) == 12, "vfs_getdents_32 must be updated.");

  // This could probably be written without the new buffer (just compacting into
  // the user-supplied buffer entry by entry), but this makes things easier to
  // reason about.
  char* buf64 = (char*)kmalloc(count);
  if (!buf64) return -ENOMEM;
  int result = vfs_getdents(fd, (kdirent_t*)buf64, count);
  if (result < 0) {
    kfree(buf64);
    return result;
  }

  char* buf32 = (char*)buf_in;
  ssize_t in_offset = 0, out_offset = 0;
  while (in_offset < result) {
    const kdirent_t* d64 = (kdirent_t*)(buf64 + in_offset);
    kdirent_32_t* d32 = (kdirent_32_t*)(buf32 + out_offset);
    d32->d_ino = d64->d_ino;
    d32->d_offset = d64->d_offset;
    d32->d_reclen = sizeof(kdirent_32_t) + kstrlen(d64->d_name) + 1;
    kstrcpy(d32->d_name, d64->d_name);
    in_offset += d64->d_reclen;
    out_offset += d32->d_reclen;
  }

  kfree(buf64);
  return out_offset;
}

int proc_getrlimit_32(int resource, struct apos_rlimit_32* lim) {
  struct apos_rlimit lim64;
  int result = proc_getrlimit(resource, &lim64);
  if (result == 0) {
    // TODO(aoates): verify this handles overflow correctly.
    lim->rlim_cur = lim64.rlim_cur;
    lim->rlim_max = lim64.rlim_max;
  }
  return result;
}

int proc_setrlimit_32(int resource, const struct apos_rlimit_32* lim) {
  struct apos_rlimit lim64;
  lim64.rlim_cur = lim->rlim_cur;
  lim64.rlim_max = lim->rlim_max;

  return proc_setrlimit(resource, &lim64);
}

_Static_assert(sizeof(apos_off_t) <= sizeof(addr_t),
               "Narrowing conversion from apos_off_t to addr_t.");
int mmap_wrapper_32(void* addr_inout32, size_t length, int prot, int flags,
                    int fd, apos_off_t offset) {
  void* addr = (void*)(addr_t)*(uint32_t*)addr_inout32;
  void* addr_out = NULL;
  int result = do_mmap(addr, length, prot, flags, fd, offset, &addr_out);
  // TODO(aoates): enforce 32-bit only mappings in mmap.
  *(uint32_t*)addr_inout32 = (addr_t)addr_out;
  return result;
}

int futex_op_32(uint32_t* uaddr, int op, uint32_t val,
                const struct apos_timespec_32* timeout, uint32_t* uaddr2,
                uint32_t val3) {
  struct apos_timespec timeout64 = timespec32to64(*timeout);
  return futex_op(uaddr, op, val, &timeout64, uaddr2, val3);
}

int apos_get_timespec_32(struct apos_timespec_32* ts32) {
  struct apos_timespec ts;
  int result = apos_get_timespec(&ts);
  if (result) {
    return result;
  }

  if (ts.tv_sec > INT32_MAX || ts.tv_nsec > INT32_MAX) {
    klogf("apos_get_timespec() overflowed 32-bit values\n");
    return -EINVAL;
  }

  *ts32 = timespec64to32(ts);
  return 0;
}
