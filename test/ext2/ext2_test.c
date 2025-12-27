// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#include "dev/dev.h"
#include "dev/static_block_dev.h"
#include "memory/block_cache.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/wait.h"
#include "test/ext2/ext2_test_data.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "vfs/ext2/ext2.h"
#include "user/include/apos/vfs/stat.h"
#include "vfs/mount.h"
#include "vfs/vfs.h"

#define EXT2_TEST_DIR "_ext2_test_dir"
#define EXT2_TEST_DEV "_ext2_test_dev"

static void validate_basic_ext2(void) {
  char buf[100];
  KEXPECT_STREQ("abcd", read_file("file1", buf, 100));
  KEXPECT_STREQ("abcd", read_file("./file1", buf, 100));
  KEXPECT_STREQ("abcd", read_file("./dir/../file1", buf, 100));
  KEXPECT_STREQ("1234", read_file("./dir/file2", buf, 100));
  KEXPECT_STREQ("1234", read_file("dir/file2", buf, 100));
  KEXPECT_EQ(-ENOENT, vfs_open("dir2", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("file3", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("dir/file3", VFS_O_RDONLY));
}

static void do_basic_ext2_test(const stblk_spec_t* spec) {
  // Create fake block dev.
  stblk_dev_t* bd = stblk_create(spec);
  KEXPECT_NE(bd, NULL);
  KEXPECT_EQ(0, vfs_mknod(EXT2_TEST_DEV, VFS_S_IFBLK, bd->dev_id));

  // Mount ext2 fs and move into it.
  KEXPECT_EQ(0, vfs_mkdir(EXT2_TEST_DIR, VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mount(EXT2_TEST_DEV, EXT2_TEST_DIR, "ext2", 0, NULL, 0));
  KEXPECT_EQ(0, vfs_chdir(EXT2_TEST_DIR));

  validate_basic_ext2();

  // Cleanup.
  KEXPECT_EQ(0, vfs_chdir(".."));
  KEXPECT_EQ(0, vfs_unmount(EXT2_TEST_DIR, 0));
  KEXPECT_EQ(0, vfs_rmdir(EXT2_TEST_DIR));
  KEXPECT_EQ(0, vfs_unlink(EXT2_TEST_DEV));
  // TODO(aoates): proper LCM of block devices and make crap like this
  // unnecessary.)
  block_cache_free_all(dev_get_block_memobj(bd->dev_id));
  stblk_destroy(bd);
}

static void mount_failure_test(void) {
  KTEST_BEGIN("ext2: mount failure");
  // Create fake block dev.
  stblk_dev_t* bd = stblk_create(&kExt2TestImg_bs1024);
  KEXPECT_NE(bd, NULL);
  KEXPECT_EQ(0, vfs_mknod(EXT2_TEST_DEV, VFS_S_IFBLK, bd->dev_id));

  // Test several different mount failures.
  KEXPECT_EQ(0, vfs_mkdir(EXT2_TEST_DIR, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOENT, vfs_mount("_doesnt_exist", EXT2_TEST_DIR, "ext2", 0, NULL, 0));
  KEXPECT_EQ(-ENOENT, vfs_mount(EXT2_TEST_DEV, "_doesnt_exist", "ext2", 0, NULL, 0));
  KEXPECT_EQ(-ENOTSUP, vfs_mount(EXT2_TEST_DIR, EXT2_TEST_DIR, "ext2", 0, NULL, 0));
  KEXPECT_EQ(-ENOTDIR, vfs_mount(EXT2_TEST_DEV, EXT2_TEST_DEV, "ext2", 0, NULL, 0));

  // Cleanup.
  KEXPECT_EQ(-EINVAL, vfs_unmount(EXT2_TEST_DIR, 0));
  KEXPECT_EQ(0, vfs_rmdir(EXT2_TEST_DIR));
  KEXPECT_EQ(0, vfs_unlink(EXT2_TEST_DEV));
  // TODO(aoates): proper LCM of block devices and make crap like this
  // unnecessary.)
  block_cache_free_all(dev_get_block_memobj(bd->dev_id));
  stblk_destroy(bd);
}

static void do_ext2_test(void* arg) {
  KTEST_BEGIN("ext2: basic ext2 (block_size=1024)");
  do_basic_ext2_test(&kExt2TestImg_bs1024);

  KTEST_BEGIN("ext2: basic ext2 (block_size=2048)");
  do_basic_ext2_test(&kExt2TestImg_bs2048);

  KTEST_BEGIN("ext2: basic ext2 (block_size=4096)");
  do_basic_ext2_test(&kExt2TestImg_bs4096);

  mount_failure_test();
}

void ext2_test(void) {
  KTEST_SUITE_BEGIN("ext2 tests");
  kpid_t child = proc_fork(&do_ext2_test, NULL);
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));
}
