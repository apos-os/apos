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

#include "common/kassert.h"
#include "memory/mmap.h"
#include "proc/signal/signal.h"
#include "syscall/wrappers32.h"
#include "vfs/vfs.h"

static struct timespec_32 timespec64to32(struct timespec ts64) {
  struct timespec_32 ts32;
  ts32.tv_sec = ts64.tv_sec;
  ts32.tv_nsec = ts64.tv_nsec;
  return ts32;
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

static void sigaction32to64(const struct sigaction_32* sa32,
                            struct sigaction* sa64) {
  _Static_assert(sizeof(struct sigaction_32) == 12,
                 "sigaction32to64 needs to be updated");
  sa64->sa_handler = (sighandler_t)(intptr_t)sa32->sa_handler;
  sa64->sa_mask = sa32->sa_mask;
  sa64->sa_flags = sa32->sa_flags;
}

static void sigaction64to32(const struct sigaction* sa64,
                            struct sigaction_32* sa32) {
  _Static_assert(sizeof(struct sigaction_32) == 12,
                 "sigaction64to32 needs to be updated");
  // TODO(aoates): test signal handling after a 64-to-32-bit exec().
  KASSERT_DBG(((addr_t)sa64->sa_handler & 0xFFFFFFFF00000000) == 0);
  sa32->sa_handler = (uint32_t)(addr_t)sa64->sa_handler;
  sa32->sa_mask = sa64->sa_mask;
  sa32->sa_flags = sa64->sa_flags;
}

int proc_sigaction_32(int signum, const struct sigaction_32* act32,
                      struct sigaction_32* oldact32) {
  struct sigaction act, oldact;
  if (act32) sigaction32to64(act32, &act);
  int result =
      proc_sigaction(signum, act32 ? &act : NULL, oldact32 ? &oldact : NULL);
  if (oldact32) sigaction64to32(&oldact, oldact32);
  return result;
}

int mmap_wrapper_32(void* addr_inout32, addr_t length, int prot, int flags,
                    int fd, addr_t offset) {
  void* addr = (void*)(addr_t)*(uint32_t*)addr_inout32;
  void* addr_out = NULL;
  int result = do_mmap(addr, length, prot, flags, fd, offset, &addr_out);
  // TODO(aoates): enforce 32-bit only mappings in mmap.
  *(uint32_t*)addr_inout32 = (addr_t)addr_out;
  return result;
}
