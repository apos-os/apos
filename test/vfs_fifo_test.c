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

#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

// Tests:
//  - symlink to FIFO
//  - read/write
//  - interrupt open, read, and write
//  - filesystem permissions
//  - invalid arguments

static void mknod_test(void) {
  KTEST_BEGIN("mknod() FIFO test");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));


  KTEST_BEGIN("mknod() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

static void stat_test(void) {
  KTEST_BEGIN("stat() FIFO test");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("fifo_test/fifo", &stat));
  KEXPECT_EQ(VFS_S_IFIFO | VFS_S_IRWXU, stat.st_mode);
  KEXPECT_EQ(1, VFS_S_ISFIFO(stat.st_mode));
  KEXPECT_GE(stat.st_ino, 0);
  KEXPECT_EQ(stat.st_nlink, 1);
  KEXPECT_EQ(0, stat.st_size);

  // TODO(aoates): test atim, mtim, ctim

  KEXPECT_LE(stat.st_blocks, 1);


  KTEST_BEGIN("lstat() FIFO test");
  apos_stat_t orig_stat = stat;
  KEXPECT_EQ(0, vfs_lstat("fifo_test/fifo", &stat));
  KEXPECT_EQ(0, kmemcmp(&stat, &orig_stat, sizeof(apos_stat_t)));

  // TODO(aoates): test fstat

  KTEST_BEGIN("stat() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

void vfs_fifo_test(void) {
  KTEST_SUITE_BEGIN("VFS FIFO test");
  const int initial_cache_size = vfs_cache_size();

  mknod_test();
  stat_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
