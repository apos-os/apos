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

#include <stdarg.h>
#include <stdint.h>

#include "common/errno.h"
#include "common/kassert.h"
#include "kmalloc.h"
#include "test/ktest.h"
#include "vfs/vfs.h"

static void open_test() {
  KTEST_BEGIN("vfs_open() test");

  vfs_log_cache();
  KEXPECT_EQ(-ENOENT, vfs_open("/test1", 0));
  vfs_log_cache();

  KEXPECT_EQ(0, vfs_open("/test1", VFS_O_CREAT));
  vfs_log_cache();

  KEXPECT_EQ(1, vfs_open("/test1", VFS_O_CREAT));
  vfs_log_cache();

  KEXPECT_EQ(2, vfs_open("/test2", VFS_O_CREAT));
  vfs_log_cache();

  KEXPECT_EQ(3, vfs_open("/test1", 0));
  vfs_log_cache();

  KTEST_BEGIN("vfs_close() test");
  KEXPECT_EQ(-EBADF, vfs_close(-10));
  KEXPECT_EQ(-EBADF, vfs_close(10000000));
  KEXPECT_EQ(-EBADF, vfs_close(5));

  KEXPECT_EQ(0, vfs_close(1));
  vfs_log_cache();

  // Make sure we reuse the fd.
  KEXPECT_EQ(1, vfs_open("/test3", VFS_O_CREAT));
  vfs_log_cache();

  // Close everything else.
  KEXPECT_EQ(0, vfs_close(3));
  vfs_log_cache();
  KEXPECT_EQ(0, vfs_close(2));
  vfs_log_cache();
  KEXPECT_EQ(0, vfs_close(0));
  vfs_log_cache();

  KTEST_BEGIN("re-vfs_open() test");
  KEXPECT_EQ(0, vfs_open("/test1", 0));
  vfs_log_cache();

  // Close everything.
  KEXPECT_EQ(0, vfs_close(0));
  KEXPECT_EQ(0, vfs_close(1));

  // TODO(aoates): test in subdirectories once mkdir works
}

void vfs_test() {
  KTEST_SUITE_BEGIN("vfs test");

  open_test();
}
