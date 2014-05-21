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
#include "common/hash.h"
#include "common/kassert.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/page_alloc.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/wait.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "vfs/mount.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs_mode.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static fs_t* ramfsA = 0x0;
static fs_t* ramfsB = 0x0;

static void basic_mount_test(void) {
  KTEST_BEGIN("vfs mount: basic mount");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/b", VFS_S_IRWXU));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  const int unmounted_mount_point_vnode_num = stat.st_ino;

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));

  // Create a file.
  int fd = vfs_open("vfs_mount_test/a/file", VFS_O_CREAT | VFS_O_RDWR,
                    VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(5, vfs_write(fd, "abcde", 5));
  KEXPECT_EQ(0, vfs_close(fd));

  edirent_t getdents_a_expected[] = {{-1, "."}, {0, ".."}, {-1, "file"}};
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a", 3, getdents_a_expected));

  // Try stat'ing it.
  KTEST_BEGIN("vfs mount: stat mount point");
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  KEXPECT_NE(0, stat.st_mode & VFS_S_IFDIR);
  // N.B.(aoates): this could technically trigger a false positive if the root
  // fs and the sub fs choose the same inode number for the directory.
  KEXPECT_NE(unmounted_mount_point_vnode_num, stat.st_ino);
  KEXPECT_EQ(ramfsA->get_root(ramfsA), stat.st_ino);
  // TODO(aoates): is there anything else we can do to verify it worked?

  KTEST_BEGIN("vfs mount: stat file under mount point");
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/file", &stat));
  KEXPECT_NE(0, stat.st_mode & VFS_S_IFREG);
  KEXPECT_EQ(5, stat.st_size);
  const int mounted_file_vnode_num = stat.st_ino;

  // Try a directory and character device as well.
  KTEST_BEGIN("vfs mount: creating directory in mounted fs");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/dir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/dir", &stat));
  KEXPECT_NE(0, stat.st_mode & VFS_S_IFDIR);

  KTEST_BEGIN("vfs mount: creating character device in mounted fs");
  KEXPECT_EQ(0, vfs_mknod("vfs_mount_test/a/chr", VFS_S_IFCHR, mkdev(0, 0)));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/chr", &stat));
  KEXPECT_NE(0, stat.st_mode & VFS_S_IFCHR);

  // Unmount it.
  KTEST_BEGIN("vfs mount: basic unmount");
  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(ramfsA, unmounted_fs);

  EXPECT_FILE_DOESNT_EXIST("vfs_mount_test/a/file");
  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/file", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  KEXPECT_EQ(unmounted_mount_point_vnode_num, stat.st_ino);

  // Now try remounting it.
  KTEST_BEGIN("vfs mount: remounting after unmount");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/b", ramfsA));

  EXPECT_FILE_EXISTS("vfs_mount_test/b/file");
  EXPECT_FILE_DOESNT_EXIST("vfs_mount_test/a/file");

  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/file", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/file", &stat));
  KEXPECT_EQ(mounted_file_vnode_num, stat.st_ino);

  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/dir", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/dir", &stat));

  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/chr", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/chr", &stat));

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b", &stat));
  KEXPECT_EQ(ramfsA->get_root(ramfsA), stat.st_ino);

  // Cleanup.
  KTEST_BEGIN("vfs mount: basic test cleanup");
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/file"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b/dir"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/chr"));

  unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));
  KEXPECT_EQ(ramfsA, unmounted_fs);

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

static void dot_dot_test(void) {
  KTEST_BEGIN("vfs mount: '..' handling test");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));

  // Create files.
  create_file("vfs_mount_test/a/file1", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/dir", VFS_S_IRWXU));

  const edirent_t getdents_a_expected[] = {{-1, "."}, {-1, ".."},
    {-1, "file1"}, {-1, "file2"}, {-1, "dir"}};
  const edirent_t getdents_expected[] = {{-1, "."}, {-1, ".."}, {-1, "a"}};

  int fd = vfs_open("vfs_mount_test/a/../a/file1", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  create_file("vfs_mount_test/a/../a/file2", "rwxrwxrwx");

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat(
          "vfs_mount_test/a/../../vfs_mount_test/./a/./../a/file1", &stat));
  KEXPECT_EQ(0, vfs_lstat(
          "vfs_mount_test/a/../../vfs_mount_test/./a/./../a", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test", &stat));
  const int vfs_mount_test_ino = stat.st_ino;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  const int a_ino = stat.st_ino;

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/..", &stat));
  KEXPECT_EQ(vfs_mount_test_ino, stat.st_ino);

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/../.", &stat));
  KEXPECT_EQ(vfs_mount_test_ino, stat.st_ino);

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/../a", &stat));
  KEXPECT_EQ(a_ino, stat.st_ino);

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/../a/.", &stat));
  KEXPECT_EQ(a_ino, stat.st_ino);

  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/.", 5,
                                  getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../a", 5,
                                  getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../a/.", 5,
                                  getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../a/../a", 5,
                                  getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../../vfs_mount_test/a", 5,
                                  getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/..", 3, getdents_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../.", 3,
                                  getdents_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../a/../.",
                                  3, getdents_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../a/..",
                                  3, getdents_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../../vfs_mount_test",
                                  3, getdents_expected));

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/dir"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file1"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file2"));

  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(ramfsA, unmounted_fs);

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

void vfs_mount_test(void) {
  KTEST_SUITE_BEGIN("vfs mount test");
  const int orig_cache_size = vfs_cache_size();

  ramfsA = ramfs_create_fs();
  ramfsB = ramfs_create_fs();

  basic_mount_test();
  dot_dot_test();

  KEXPECT_EQ(orig_cache_size, vfs_cache_size());

  // TODO(aoates): free the ramfses.
}
