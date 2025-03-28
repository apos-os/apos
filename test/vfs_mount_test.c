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
#include "common/kprintf.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/mmap.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/notification.h"
#include "proc/preemption_hook.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "test/test_params.h"
#include "test/vfs_test_util.h"
#include "vfs/mount.h"
#include "vfs/ramfs.h"
#include "vfs/testfs.h"
#include "vfs/util.h"
#include "vfs/vfs_internal.h"
#include "vfs/vfs_mode.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"
#include "vfs/vnode.h"

static fs_t* ramfsA = 0x0;
static fs_t* ramfsB = 0x0;

static void append_path(char* first, const char* second) {
  int len = kstrlen(first);
  if (len > 0 && first[len-1] != '/') {
    kstrcat(first, "/");
  }
  kstrcat(first, second);
}

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

  // Cannot mount the same filesystem in two places.
  KEXPECT_EQ(-EBUSY, vfs_mount_fs("vfs_mount_test/b", ramfsA));

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
  KEXPECT_EQ(0, vfs_mknod("vfs_mount_test/a/chr", VFS_S_IFCHR, kmakedev(0, 0)));
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


  KTEST_BEGIN("vfs mount: cannot mount on non-existant directory");
  KEXPECT_EQ(-ENOENT, vfs_mount_fs("vfs_mount_test2", ramfsB));
  KEXPECT_EQ(-ENOENT, vfs_mount_fs("vfs_mount_test/not_there", ramfsB));


  KTEST_BEGIN("vfs mount: cannot mount on file");
  create_file("vfs_mount_test/file", "rwxrwxrwx");
  KEXPECT_EQ(-ENOTDIR, vfs_mount_fs("vfs_mount_test/file", ramfsB));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/file"));


  KTEST_BEGIN("vfs mount: cannot mount on character device");
  KEXPECT_EQ(0, vfs_mknod("vfs_mount_test/chr", VFS_S_IFCHR, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_mount_fs("vfs_mount_test/chr", ramfsB));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/chr"));


  KTEST_BEGIN("vfs mount: cannot mount on block device");
  KEXPECT_EQ(0, vfs_mknod("vfs_mount_test/blk", VFS_S_IFBLK, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_mount_fs("vfs_mount_test/blk", ramfsB));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/blk"));

  // TODO(aoates): test symlinks.

  unmounted_fs = 0x0;
  KTEST_BEGIN("vfs mount: cannot unmount a file");
  create_file("vfs_mount_test/file", "rwxrwxrwx");
  KEXPECT_EQ(-ENOTDIR, vfs_unmount_fs("vfs_mount_test/file", &unmounted_fs));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/file"));

  KTEST_BEGIN("vfs mount: cannot unmount non-moint-point directory");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/not_mount", VFS_S_IRWXU));
  KEXPECT_EQ(-EINVAL, vfs_unmount_fs("vfs_mount_test/not_mount",
                                     &unmounted_fs));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/not_mount"));

  KTEST_BEGIN("vfs mount: cannot unmount nonexistant mount point");
  KEXPECT_EQ(-ENOENT, vfs_unmount_fs("vfs_mount_test/doesnt_exist",
                                     &unmounted_fs));


  KTEST_BEGIN("vfs mount: invalid vfs_mount_fs() args");
  KEXPECT_EQ(-EINVAL, vfs_mount_fs(0x0, ramfsB));
  KEXPECT_EQ(-EINVAL, vfs_mount_fs("vfs_mount_test/a", 0x0));


  KTEST_BEGIN("vfs mount: invalid vfs_unmount_fs() args");
  KEXPECT_EQ(-EINVAL, vfs_unmount_fs(0x0, &unmounted_fs));
  KEXPECT_EQ(-EINVAL, vfs_unmount_fs("vfs_mount_test/a", 0x0));


  // Cleanup.
  KTEST_BEGIN("vfs mount: basic test cleanup");
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/file"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b/dir"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/chr"));

  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));
  KEXPECT_EQ(ramfsA, unmounted_fs);

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

static void do_fstat_path(const char* path, apos_stat_t* stat) {
  int fd = vfs_open(path, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_fstat(fd, stat));
  KEXPECT_EQ(0, vfs_close(fd));
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

  // As above, but do open()+fstat() rather than lstat.
  do_fstat_path("vfs_mount_test/a/..", &stat);
  KEXPECT_EQ(vfs_mount_test_ino, stat.st_ino);

  do_fstat_path("vfs_mount_test/a/../.", &stat);
  KEXPECT_EQ(vfs_mount_test_ino, stat.st_ino);

  do_fstat_path("vfs_mount_test/a/../a", &stat);
  KEXPECT_EQ(a_ino, stat.st_ino);

  do_fstat_path("vfs_mount_test/a/../a/.", &stat);
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

// Check that the cwd is equal to orig_cwd joined with relpath.
#define EXPECT_CWD(orig_cwd, relpath) do { \
  char* _expected_cwd = kmalloc(2 * VFS_MAX_PATH_LENGTH); \
  char* _actual_cwd = kmalloc(VFS_MAX_PATH_LENGTH); \
  kstrcpy(_expected_cwd, (orig_cwd)); \
  append_path(_expected_cwd, (relpath)); \
  KEXPECT_GE(vfs_getcwd(_actual_cwd, VFS_MAX_PATH_LENGTH), 0); \
  KEXPECT_STREQ(_expected_cwd, _actual_cwd); \
  kfree(_expected_cwd); \
  kfree(_actual_cwd); \
} while (0)

static void mount_cwd_test(void) {
  KTEST_BEGIN("vfs mount: cwd into mount test");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));

  char* orig_cwd = kmalloc(VFS_MAX_PATH_LENGTH);
  KEXPECT_GE(vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH), 0);

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));

  // Create files.
  create_file("vfs_mount_test/a/file1", "rwxrwxrwx");
  create_file("vfs_mount_test/a/file2", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/dir", VFS_S_IRWXU));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  const int mounted_root_ino = stat.st_ino;

  edirent_t getdents_a_expected[] = {{mounted_root_ino, "."}, {-1, ".."},
    {-1, "file1"}, {-1, "file2"}, {-1, "dir"}};
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("vfs_mount_test/a/../a",
                                  5, getdents_a_expected));

  // Now cd into the directory above the mount point.
  KTEST_BEGIN("vfs mount: cwd above mount point test");
  KEXPECT_EQ(0, vfs_chdir("vfs_mount_test"));
  KEXPECT_EQ(0, compare_dirents_p("a", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("../vfs_mount_test/a", 5,
                                  getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("a/../a", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("a/././../a/.", 5, getdents_a_expected));

  EXPECT_CWD(orig_cwd, "vfs_mount_test");

  // Now cd into the mount point itself.
  KTEST_BEGIN("vfs mount: cwd in mount point test");
  KEXPECT_EQ(0, vfs_chdir("a"));
  KEXPECT_EQ(0, compare_dirents_p(".", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("./", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("././.", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("../a", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("../a/../a/.", 5, getdents_a_expected));

  EXPECT_CWD(orig_cwd, "vfs_mount_test/a");

  // ...and now cd into a directory below the mount point.
  KTEST_BEGIN("vfs mount: cwd below mount point test");
  KEXPECT_EQ(0, vfs_chdir("dir"));
  KEXPECT_EQ(0, compare_dirents_p("..", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("../../a", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("../../a/.", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p("./.././", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p(".././dir/..", 5, getdents_a_expected));
  KEXPECT_EQ(0, compare_dirents_p(".././dir/../.", 5, getdents_a_expected));

  EXPECT_CWD(orig_cwd, "vfs_mount_test/a/dir");

  KTEST_BEGIN("vfs cwd test: cleanup");
  KEXPECT_EQ(0, vfs_chdir(orig_cwd));

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/dir"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file1"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file2"));

  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(ramfsA, unmounted_fs);

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
  kfree(orig_cwd);
}

static void rmdir_mount_test(void) {
  KTEST_BEGIN("vfs mount: rmdir mount test");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));

  char orig_cwd[VFS_MAX_PATH_LENGTH];
  KEXPECT_GE(vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH), 0);

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));

  KEXPECT_EQ(-EISDIR, vfs_unlink("vfs_mount_test"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("vfs_mount_test/a"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("vfs_mount_test/a/."));
  KEXPECT_EQ(-EBUSY, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_NE(0, vfs_rmdir("vfs_mount_test/a/."));  // Could be EBUSY or EINVAL
  KEXPECT_EQ(-EBUSY, vfs_rmdir("vfs_mount_test/a/../a"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("vfs_mount_test/a/.."));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/b", VFS_S_IRWXU));
  KEXPECT_EQ(-EBUSY, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(-EINVAL, vfs_rmdir("vfs_mount_test/a/."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("vfs_mount_test/a/b/.."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("vfs_mount_test/a/b/../"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/b/"));

  // Now cd into the directory above the mount point.
  KEXPECT_EQ(0, vfs_chdir("vfs_mount_test"));

  KEXPECT_EQ(-EISDIR, vfs_unlink("."));
  KEXPECT_EQ(-EISDIR, vfs_unlink("a"));
  KEXPECT_EQ(-EINVAL, vfs_rmdir("."));
  KEXPECT_EQ(-EINVAL, vfs_rmdir("./."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("./a/.."));
  KEXPECT_EQ(-EBUSY, vfs_rmdir("a"));
  KEXPECT_NE(0, vfs_rmdir("a/."));  // Could be EBUSY or EINVAL
  KEXPECT_EQ(-EBUSY, vfs_rmdir("a/../a"));

  // Now cd into the mount point itself.
  KEXPECT_EQ(0, vfs_chdir("a"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("."));
  KEXPECT_EQ(-EISDIR, vfs_unlink(".."));
  KEXPECT_EQ(-EISDIR, vfs_unlink("../a"));
  KEXPECT_NE(0, vfs_rmdir("."));
  KEXPECT_NE(0, vfs_rmdir("./."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir(".."));
  KEXPECT_NE(0, vfs_rmdir("../."));  // Could be ENOTEMPTY or EINVAL
  KEXPECT_NE(0, vfs_rmdir("../a"));  // Could be EBUSY or EINVAL
  KEXPECT_NE(0, vfs_rmdir("../a/."));   // Could be EBUSY or EINVAL

  // ...and now cd into a directory below the mount point.
  KEXPECT_EQ(0, vfs_mkdir("dir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_chdir("dir"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("."));
  KEXPECT_EQ(-EISDIR, vfs_unlink(".."));
  KEXPECT_EQ(-EISDIR, vfs_unlink("../.."));
  KEXPECT_EQ(-EINVAL, vfs_rmdir("."));
  KEXPECT_EQ(-EINVAL, vfs_rmdir("./."));
  KEXPECT_NE(0, vfs_rmdir(".."));
  KEXPECT_NE(0, vfs_rmdir("../."));
  KEXPECT_NE(0, vfs_rmdir("../../a"));

  KTEST_BEGIN("vfs cwd test: cleanup");
  KEXPECT_EQ(0, vfs_chdir(orig_cwd));

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/dir"));
  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

static void chown_chmod_test(void) {
  KTEST_BEGIN("vfs mount: lchown/chmod mount test");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/b", VFS_S_IRWXU));

  char orig_cwd[VFS_MAX_PATH_LENGTH];
  KEXPECT_GE(vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH), 0);

  char abs_mount_a[VFS_MAX_PATH_LENGTH];
  kstrcpy(abs_mount_a, orig_cwd);
  append_path(abs_mount_a, "vfs_mount_test/a");

  const kmode_t orig_a_mode = get_mode("vfs_mount_test/a");

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/dir", VFS_S_IRWXU));

  KEXPECT_EQ(0, vfs_lchown("vfs_mount_test/a", 1, 1));
  EXPECT_OWNER_IS("vfs_mount_test/a", 1, 1);

  KEXPECT_EQ(0, vfs_chmod("vfs_mount_test/a", VFS_S_IRWXG));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXG, get_mode("vfs_mount_test/a"));

  // Now cd into the mount point itself.
  KEXPECT_EQ(0, vfs_chdir("vfs_mount_test/a"));

  KEXPECT_EQ(0, vfs_lchown(".", 2, 2));
  EXPECT_OWNER_IS(abs_mount_a, 2, 2);
  KEXPECT_EQ(0, vfs_lchown("../a", 3, 3));
  EXPECT_OWNER_IS(abs_mount_a, 3, 3);
  KEXPECT_EQ(0, vfs_lchown("..", 4, 4));
  EXPECT_OWNER_IS(abs_mount_a, 3, 3);

  KEXPECT_EQ(0, vfs_chmod(".", VFS_S_IRWXO));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXO, get_mode(abs_mount_a));
  KEXPECT_EQ(0, vfs_chmod("..", VFS_S_IWUSR));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXO, get_mode(abs_mount_a));

  // ...and to a directory below the mount point.
  KEXPECT_EQ(0, vfs_chdir("dir"));

  KEXPECT_EQ(0, vfs_lchown("..", 5, 5));
  EXPECT_OWNER_IS(abs_mount_a, 5, 5);
  KEXPECT_EQ(0, vfs_lchown("../../a", 6, 6));
  EXPECT_OWNER_IS(abs_mount_a, 6, 6);
  KEXPECT_EQ(0, vfs_lchown("../../a/.", 7, 7));
  EXPECT_OWNER_IS(abs_mount_a, 7, 7);

  KEXPECT_EQ(0, vfs_chmod("..", VFS_S_IRGRP));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRGRP, get_mode(abs_mount_a));
  KEXPECT_EQ(0, vfs_chmod("../../a", VFS_S_IXGRP));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IXGRP, get_mode(abs_mount_a));

  // Make sure our changes to the mount point's parent went through.
  KEXPECT_EQ(0, vfs_chdir(orig_cwd));
  EXPECT_OWNER_IS("vfs_mount_test", 4, 4);
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IWUSR, get_mode("vfs_mount_test"));

  // Now make sure if we unmount, the orginial mount point is unchanged.
  KTEST_BEGIN("vfs mount: lchown/chmod modify mounted fs, not mount point");

  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));

  EXPECT_OWNER_IS("vfs_mount_test/a", SUPERUSER_UID, SUPERUSER_GID);
  KEXPECT_EQ(orig_a_mode, get_mode("vfs_mount_test/a"));

  // Now make sure if we remount, the owner/mode are reflected at the new moint
  // point.
  KTEST_BEGIN("vfs mount: lchown/chmod remounted keep attributes");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/b", ramfsA));

  EXPECT_OWNER_IS("vfs_mount_test/a", SUPERUSER_UID, SUPERUSER_GID);
  EXPECT_OWNER_IS("vfs_mount_test/b", 7, 7);

  KEXPECT_EQ(orig_a_mode, get_mode("vfs_mount_test/a"));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IXGRP, get_mode("vfs_mount_test/b"));

  KTEST_BEGIN("vfs cwd test: cleanup");
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b/dir"));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

typedef struct {
  notification_t child_ran;
  notification_t done;
  void* map_addr;
  void* map_addr2;
  bool first_parent_exit;
} unmount_busy_test_args_t;

static void unmount_busy_child2(void* arg) {
  unmount_busy_test_args_t* args = (unmount_busy_test_args_t*)arg;

  int x = *(volatile int*)args->map_addr;  // Force a page-in.
  KEXPECT_EQ(0, x);
  x = *(volatile int*)args->map_addr2;

  *(volatile int*)((intptr_t)args->map_addr + 2 * PAGE_SIZE) = 10;
  *(volatile int*)((intptr_t)args->map_addr2 + 2 * PAGE_SIZE) = 20;

  ntfn_notify(&args->child_ran);
  ntfn_await(&args->done);
}

static void unmount_busy_child1(void* arg) {
  unmount_busy_test_args_t* args = (unmount_busy_test_args_t*)arg;

  int x = *(volatile int*)args->map_addr;  // Force a page-in.
  KEXPECT_EQ(0, x);
  x = *(volatile int*)args->map_addr2;

  *(volatile int*)((intptr_t)args->map_addr + PAGE_SIZE) = 5;
  *(volatile int*)((intptr_t)args->map_addr2 + PAGE_SIZE) = 15;

  kpid_t child = proc_fork(&unmount_busy_child2, arg);
  if (!args->first_parent_exit) {
    KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));
  }
}

static void* unmount_thread1(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  notification_t* done = (notification_t*)arg;
  int orig_fd = vfs_open("vfs_mount_test", VFS_O_RDONLY | VFS_O_DIRECTORY);
  file_t* file = NULL;
  KEXPECT_EQ(0, lookup_fd(orig_fd, &file));
  while (!ntfn_has_been_notified(done)) {
    vfs_ref(file->vnode);
    sched_preempt_me(5);
    vfs_put(file->vnode);
  }
  file_unref(file);
  KEXPECT_EQ(0, vfs_close(orig_fd));
  sched_disable_preemption();
  return NULL;
}

static void* unmount_thread2(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  notification_t* done = (notification_t*)arg;
  apos_stat_t stat;
  while (!ntfn_has_been_notified(done)) {
    int fd = vfs_open("vfs_mount_test/a", VFS_O_RDONLY | VFS_O_DIRECTORY);
    KEXPECT_GE(fd, 0);
    KEXPECT_EQ(0, vfs_fstat(fd, &stat));

    KEXPECT_EQ(0, vfs_close(fd));
    fd = vfs_open("vfs_mount_test/a/dir", VFS_O_RDONLY | VFS_O_DIRECTORY);
    KEXPECT_GE(fd, 0);
    KEXPECT_EQ(0, vfs_fstat(fd, &stat));
    KEXPECT_EQ(0, vfs_close(fd));
  }
  sched_disable_preemption();
  return NULL;
}

static void unmount_thread_test(const char* abs_mount_a) {
  KTEST_BEGIN("vfs mount: multithreaded busy unmount test");

  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  int fd = vfs_open("vfs_mount_test/a", VFS_O_RDONLY | VFS_O_DIRECTORY);
  KEXPECT_GE(fd, 0);

  notification_t done;
  ntfn_init(&done);
  kthread_t thread1, thread2;
  KEXPECT_EQ(0, proc_thread_create(&thread1, &unmount_thread1, &done));
  KEXPECT_EQ(0, proc_thread_create(&thread2, &unmount_thread2, &done));

  fs_t* unmounted_fs = 0x0;
  for (int i = 0; i < 10 * CONCURRENCY_TEST_ITERS_MULT; ++i) {
    KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));
  }
  ntfn_notify(&done);
  KEXPECT_EQ(NULL, kthread_join(thread1));
  KEXPECT_EQ(NULL, kthread_join(thread2));

  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));
}

static void unmount_busy_test(void) {
  KTEST_BEGIN("vfs mount: cannot unmount busy directory test setup");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));

  char orig_cwd[VFS_MAX_PATH_LENGTH];
  KEXPECT_GE(vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH), 0);

  char abs_mount_a[VFS_MAX_PATH_LENGTH];
  kstrcpy(abs_mount_a, orig_cwd);
  append_path(abs_mount_a, "vfs_mount_test/a");

  fs_t* unmounted_fs = 0x0;

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/dir", VFS_S_IRWXU));

  KTEST_BEGIN("vfs mount: cannot unmount directory with process cwd in it");
  KEXPECT_EQ(0, vfs_chdir("vfs_mount_test/a"));
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));
  KEXPECT_EQ(0, vfs_chdir("dir"));
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  KEXPECT_EQ(0, vfs_chdir(orig_cwd));
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));


  KTEST_BEGIN("vfs mount: cannot unmount directory with open file in it");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  int fd = vfs_open("vfs_mount_test/a/file", VFS_O_CREAT | VFS_O_RDWR,
                    VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));


  KTEST_BEGIN("vfs mount: cannot unmount directory mmap'd file in it");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  fd = vfs_open("vfs_mount_test/a/file", VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);

  void* map_addr = 0x0;
  KEXPECT_EQ(0, do_mmap(0x0, PAGE_SIZE, KPROT_EXEC | KPROT_READ, KMAP_PRIVATE,
                        fd, 0, &map_addr));
  KEXPECT_EQ(0, vfs_close(fd));

  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  KEXPECT_EQ(0, do_munmap(map_addr, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));


  // As above, but page in something from the file.
  KTEST_BEGIN("vfs mount: cannot unmount directory mmap'd file in it (#2)");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  fd = vfs_open("vfs_mount_test/a/file", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_ftruncate(fd, PAGE_SIZE * 2));
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  KEXPECT_EQ(0, do_mmap(0x0, PAGE_SIZE, KPROT_EXEC | KPROT_READ, KMAP_PRIVATE,
                        fd, 0, &map_addr));
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  int x = *(volatile int*)map_addr;  // Force a page-in.
  KEXPECT_EQ(0, x);

  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  KEXPECT_EQ(0, do_munmap(map_addr, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));


  // As above, but more processes, shadow objects, etc.
  KTEST_BEGIN("vfs mount: cannot unmount directory mmap'd file in it (#3)");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  // Create an open file first that _can_ be flushed later.
  int fd2 =
      vfs_open("vfs_mount_test/a/file2", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_EQ(0, vfs_ftruncate(fd2, PAGE_SIZE * 3));
  KEXPECT_EQ(0, do_mmap(0x0, 3 * PAGE_SIZE, KPROT_EXEC | KPROT_READ,
                        KMAP_PRIVATE, fd2, 0, &map_addr));
  KEXPECT_EQ(0, vfs_close(fd2));
  x = *(volatile int*)map_addr;  // Force a page-in.
  KEXPECT_EQ(0, x);
  KEXPECT_EQ(0, do_munmap(map_addr, PAGE_SIZE * 3));

  // Now open a file that we'll mmap and dirty in various child processes.
  fd = vfs_open("vfs_mount_test/a/file", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_ftruncate(fd, PAGE_SIZE * 4));

  unmount_busy_test_args_t busy_child_args;
  ntfn_init(&busy_child_args.child_ran);
  ntfn_init(&busy_child_args.done);
  busy_child_args.first_parent_exit = false;
  KEXPECT_EQ(0,
             do_mmap(0x0, 3 * PAGE_SIZE, KPROT_EXEC | KPROT_READ | KPROT_WRITE,
                     KMAP_PRIVATE, fd, 0, &busy_child_args.map_addr));
  KEXPECT_EQ(0,
             do_mmap(0x0, 3 * PAGE_SIZE, KPROT_EXEC | KPROT_READ | KPROT_WRITE,
                     KMAP_SHARED, fd, 0, &busy_child_args.map_addr2));
  // One more mapping that we create then immediately unmap.
  KEXPECT_EQ(0, do_mmap(0x0, PAGE_SIZE, KPROT_EXEC | KPROT_READ | KPROT_WRITE,
                        KMAP_SHARED, fd, 3 * PAGE_SIZE, &map_addr));
  x = *(volatile int*)map_addr;
  *(volatile int*)map_addr = 5;
  KEXPECT_EQ(0, do_munmap(map_addr, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_close(fd));

  kpid_t child = proc_fork(&unmount_busy_child1, &busy_child_args);
  ntfn_await(&busy_child_args.child_ran);

  KEXPECT_EQ(0, do_munmap(busy_child_args.map_addr, 3 * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(busy_child_args.map_addr2, 3 * PAGE_SIZE));

  // Now should have various shadow chains and pages.
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  ntfn_notify(&busy_child_args.done);
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));
  // This should clean up all the shadow objects and orphaned pages.
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));


  // As above, middle process exits.
  KTEST_BEGIN("vfs mount: cannot unmount directory mmap'd file in it (#4)");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  fd = vfs_open("vfs_mount_test/a/file", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_ftruncate(fd, PAGE_SIZE * 4));

  ntfn_init(&busy_child_args.child_ran);
  ntfn_init(&busy_child_args.done);
  busy_child_args.first_parent_exit = true;
  KEXPECT_EQ(0,
             do_mmap(0x0, 3 * PAGE_SIZE, KPROT_EXEC | KPROT_READ | KPROT_WRITE,
                     KMAP_PRIVATE, fd, 0, &busy_child_args.map_addr));
  KEXPECT_EQ(0,
             do_mmap(0x0, 3 * PAGE_SIZE, KPROT_EXEC | KPROT_READ | KPROT_WRITE,
                     KMAP_SHARED, fd, 0, &busy_child_args.map_addr2));
  // One more mapping that we create then immediately unmap.
  KEXPECT_EQ(0, do_mmap(0x0, PAGE_SIZE, KPROT_EXEC | KPROT_READ | KPROT_WRITE,
                        KMAP_SHARED, fd, 3 * PAGE_SIZE, &map_addr));
  x = *(volatile int*)map_addr;
  *(volatile int*)map_addr = 5;
  KEXPECT_EQ(0, do_munmap(map_addr, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_close(fd));

  child = proc_fork(&unmount_busy_child1, &busy_child_args);
  ntfn_await(&busy_child_args.child_ran);

  KEXPECT_EQ(0, do_munmap(busy_child_args.map_addr, 3 * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(busy_child_args.map_addr2, 3 * PAGE_SIZE));

  // Now should have various shadow chains and pages.
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  // Let child finish before we let grandchild finish.
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));
  ntfn_notify(&busy_child_args.done);
  // We can't wait for the grandchild, so just give it time to finish.
  for (int i = 0; i < 5; ++i) scheduler_yield();
  // This should clean up all the shadow objects and orphaned pages.
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));


  KTEST_BEGIN("vfs mount: cannot unmount directory with root open");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  fd = vfs_open("vfs_mount_test/a", VFS_O_RDONLY | VFS_O_DIRECTORY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unmount_fs(abs_mount_a, &unmounted_fs));

  unmount_thread_test(abs_mount_a);

  KTEST_BEGIN("vfs busy mount test: cleanup");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/dir"));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

// Test mounting another filesystem under a mount.
static void mount_under_mount_test(void) {
  KTEST_BEGIN("vfs mount: multi mount setup");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/b", VFS_S_IRWXU));

  fs_t* unmounted_fs = 0x0;

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/b", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a/b", ramfsB));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/b/dir", VFS_S_IRWXU));
  create_file("vfs_mount_test/a/b/dir/file", "rwxrwxrwx");

  KTEST_BEGIN("vfs mount: cannot unmount a mount with another mount inside");
  KEXPECT_EQ(-EBUSY, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  const int mount_a_ino = stat.st_ino;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b", &stat));
  const int mount_b_ino = stat.st_ino;

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b/dir/..", &stat));
  KEXPECT_EQ(mount_b_ino, stat.st_ino);

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b/dir/../..", &stat));
  KEXPECT_EQ(mount_a_ino, stat.st_ino);

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b/..", &stat));
  KEXPECT_EQ(mount_a_ino, stat.st_ino);

  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a/b", &unmounted_fs));
  KEXPECT_EQ(ramfsB, unmounted_fs);

  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/b/dir", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b", &stat));
  KEXPECT_NE(mount_b_ino, stat.st_ino);
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b/..", &stat));
  KEXPECT_EQ(mount_a_ino, stat.st_ino);

  KTEST_BEGIN("vfs mount: remounting previously sub-mounted fs");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/b", ramfsB));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b", &stat));
  KEXPECT_EQ(mount_b_ino, stat.st_ino);
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/dir/..", &stat));
  KEXPECT_EQ(mount_b_ino, stat.st_ino);
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/dir", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/dir/file", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a", &stat));
  KEXPECT_EQ(mount_a_ino, stat.st_ino);

  KTEST_BEGIN("vfs sub-mount test: cleanup");
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/b"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/dir/file"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b/dir"));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

// Test mounting on an existing mount point (recursive mount).
static void double_mount_test(void) {
  KTEST_BEGIN("vfs mount: recursive mount setup");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));

  KEXPECT_EQ(0, vfs_lchown("vfs_mount_test/a", 1, 1));

  fs_t* unmounted_fs = 0x0;

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  create_file("vfs_mount_test/a/a_file", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_lchown("vfs_mount_test/a", 2, 2));

  KTEST_BEGIN("vfs mount: can mount on existing mount point");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsB));

  apos_stat_t stat;
  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/a_file", &stat));
  create_file("vfs_mount_test/a/b_file", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_lchown("vfs_mount_test/a", 3, 3));

  // Unmount the second fs.
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(ramfsB, unmounted_fs);

  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/b_file", &stat));
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/a_file", &stat));
  EXPECT_OWNER_IS("vfs_mount_test/a", 2, 2);

  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/a_file"));

  // Unmount the first fs.
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(ramfsA, unmounted_fs);

  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/b_file", &stat));
  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/a_file", &stat));
  EXPECT_OWNER_IS("vfs_mount_test/a", 1, 1);

  // Remount the second fs to make sure b_file is still there.
  KTEST_BEGIN("vfs mount: can mount on existing mount point");
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsB));

  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/b_file", &stat));
  KEXPECT_EQ(-ENOENT, vfs_lstat("vfs_mount_test/a/a_file", &stat));
  EXPECT_OWNER_IS("vfs_mount_test/a", 3, 3);

  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/b_file"));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(ramfsB, unmounted_fs);

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

static void too_many_mounts_test(void) {
  KTEST_BEGIN("vfs mount: too many mounts");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  fs_t* unmounted_fs;

  fs_t* fses[VFS_MAX_FILESYSTEMS];
  for (int i = 0; i < VFS_MAX_FILESYSTEMS; ++i) {
    fses[i] = testfs_create();
  }

  const int num_to_mount = VFS_MAX_FILESYSTEMS - vfs_mounted_fs_count();

  char name[20];
  for (int i = 0; i < num_to_mount; ++i) {
    ksprintf(name, "vfs_mount_test/m%d", i);
    KEXPECT_EQ(0, vfs_mkdir(name, VFS_S_IRWXU));

    KEXPECT_EQ(0, vfs_mount_fs(name, fses[i]));
  }

  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/last", VFS_S_IRWXU));
  KEXPECT_EQ(-ENOMEM, vfs_mount_fs("vfs_mount_test/last",
                                   fses[num_to_mount]));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/last"));

  for (int i = 0; i < num_to_mount; ++i) {
    ksprintf(name, "vfs_mount_test/m%d", i);

    KEXPECT_EQ(0, vfs_unmount_fs(name, &unmounted_fs));
    KEXPECT_EQ(0, vfs_rmdir(name));
  }

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));

  for (int i = 0; i < VFS_MAX_FILESYSTEMS; ++i) {
    fses[i]->destroy_fs(fses[i]);
  }
}

static void symlink_mount_test(void) {
  KTEST_BEGIN("vfs mount: symlink across mounts");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/dir", VFS_S_IRWXU));

  // Create a file and link to it.
  int fd = vfs_open("vfs_mount_test/a/file", VFS_O_CREAT | VFS_O_RDWR,
                    VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(5, vfs_write(fd, "abcde", 5));
  KEXPECT_EQ(0, vfs_close(fd));

  KEXPECT_EQ(0, vfs_symlink("a/file", "vfs_mount_test/link"));
  EXPECT_FILE_EXISTS("vfs_mount_test/link");

  create_file("vfs_mount_test/rootfile", "rwxrwxrwx");
  KEXPECT_EQ(0, vfs_symlink("../rootfile", "vfs_mount_test/a/mountlink"));
  EXPECT_FILE_EXISTS("vfs_mount_test/a/mountlink");


  KTEST_BEGIN("vfs mount: symlink to mount");
  KEXPECT_EQ(0, vfs_symlink("a", "vfs_mount_test/link_to_mount"));
  fd = vfs_open("vfs_mount_test/link_to_mount", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/link_to_mount"));


  KTEST_BEGIN("vfs mount: symlink to mount (inside mount)");
  KEXPECT_EQ(0, vfs_symlink(".", "vfs_mount_test/a/link_to_mount"));
  KEXPECT_EQ(0, vfs_symlink("../a", "vfs_mount_test/a/link_to_mount2"));
  fd = vfs_open("vfs_mount_test/a/link_to_mount", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);
  fd = vfs_open("vfs_mount_test/a/link_to_mount2", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/link_to_mount"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/link_to_mount2"));

  KTEST_BEGIN("vfs mount: symlink across mounts");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/b", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/b", ramfsB));

  KEXPECT_EQ(0, vfs_symlink("../b", "vfs_mount_test/a/link1"));
  create_file("vfs_mount_test/a/link1/linkfile1", "rwxrwxrwx");
  EXPECT_FILE_EXISTS("vfs_mount_test/b/linkfile1");
  KEXPECT_EQ(0, compare_dirents_p(
                    "vfs_mount_test/a/link1", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "linkfile1"}}));
  KEXPECT_EQ(0, compare_dirents_p(
                    "vfs_mount_test/b", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "linkfile1"}}));

  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/link1/dir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("../b/dir", "vfs_mount_test/a/link2"));
  create_file("vfs_mount_test/a/link2/linkfile2", "rwxrwxrwx");
  EXPECT_FILE_EXISTS("vfs_mount_test/b/dir/linkfile2");

  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/link1"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/linkfile1"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/dir/linkfile2"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b/dir"));

  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/link"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/rootfile"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/mountlink"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a/dir"));


  KTEST_BEGIN("vfs mount: hard link across mounts");
  create_file("vfs_mount_test/a/file", "rwxrwxrwx");
  KEXPECT_EQ(-EXDEV, vfs_link("vfs_mount_test/a/file", "vfs_mount_test/b/lnk"));
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("vfs_mount_test/a/file", &stat));
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_NE(0, VFS_S_ISREG(stat.st_mode));
  KEXPECT_EQ(-ENOENT, vfs_stat("vfs_mount_test/b/lnk", &stat));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file"));


  // Cleanup.
  KTEST_BEGIN("vfs mount: basic test cleanup");
  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

static void rename_mount_test(void) {
  KTEST_BEGIN("vfs mount: rename mount test");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/b", VFS_S_IRWXU));

  char orig_cwd[VFS_MAX_PATH_LENGTH];
  KEXPECT_GE(vfs_getcwd(orig_cwd, VFS_MAX_PATH_LENGTH), 0);

  // Do the mount.
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/b", ramfsB));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a/a2", VFS_S_IRWXU));

  KTEST_BEGIN("vfs mount: rename() across filesystems fails");
  create_file("vfs_mount_test/a/f", "rwxrwxrwx");
  create_file("vfs_mount_test/b/f2", "rwxrwxrwx");
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/f", "vfs_mount_test/b/f"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/f", "vfs_mount_test/b/f2"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a", "vfs_mount_test/b/c"));

  KTEST_BEGIN("vfs mount: rename() filesystem mount point");
  // Note: many of these could be EBUSY, EXDEV, or EINVAL depending on the order
  // of checks and mount resolutions.
  KEXPECT_EQ(-EBUSY, vfs_rename("vfs_mount_test/a", "vfs_mount_test/c"));
  KEXPECT_EQ(-EBUSY, vfs_rename("vfs_mount_test/a/", "vfs_mount_test/c"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/.", "vfs_mount_test/c"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/a2/..", "vfs_mount_test/c"));
  KEXPECT_EQ(-EBUSY, vfs_rename("vfs_mount_test/a", "vfs_mount_test/b"));
  KEXPECT_EQ(-EBUSY, vfs_rename("vfs_mount_test/a/", "vfs_mount_test/b"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/.", "vfs_mount_test/b"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/a2/..", "vfs_mount_test/b"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a", "vfs_mount_test/a/."));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a", "vfs_mount_test/a/a2"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a", "vfs_mount_test/a/a2/"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a", "vfs_mount_test/a/a2/c"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/a/", "vfs_mount_test/a/a2/c"));
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("vfs_mount_test/a", &stat));
  KEXPECT_EQ(0, vfs_stat("vfs_mount_test/b", &stat));
  KEXPECT_EQ(-ENOENT, vfs_stat("vfs_mount_test/c", &stat));
  KEXPECT_EQ(-ENOENT, vfs_stat("vfs_mount_test/c/f", &stat));

  KTEST_BEGIN("vfs mount: rename() over filesystem mount point");
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/f2"));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/dir", VFS_S_IRWXU));
  KEXPECT_EQ(-EBUSY, vfs_rename("vfs_mount_test/dir", "vfs_mount_test/b"));
  KEXPECT_EQ(-EXDEV, vfs_rename("vfs_mount_test/dir", "vfs_mount_test/b/."));
  KEXPECT_EQ(-EXDEV,
             vfs_rename("vfs_mount_test/dir", "vfs_mount_test/a/a2/.."));
  KEXPECT_EQ(0, vfs_stat("vfs_mount_test/a", &stat));
  KEXPECT_EQ(0, vfs_stat("vfs_mount_test/b", &stat));
  KEXPECT_EQ(0, vfs_stat("vfs_mount_test/dir", &stat));

  KTEST_BEGIN("vfs mount test: rename cleanup");
  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/dir"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

static void mmap_same_vnode_test(void) {
  KTEST_BEGIN("vfs mount: mmap the same vnode");
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/a", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("vfs_mount_test/b", VFS_S_IRWXU));

  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/a", ramfsA));
  KEXPECT_EQ(0, vfs_mount_fs("vfs_mount_test/b", ramfsB));

  // Create a file in each.
  int fd1 =
      vfs_open("vfs_mount_test/a/file", VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRWXU);
  KEXPECT_GE(fd1, 0);
  KEXPECT_EQ(2, vfs_write(fd1, "a", 2));
  int fd2 =
      vfs_open("vfs_mount_test/b/file", VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRWXU);
  KEXPECT_GE(fd2, 0);
  KEXPECT_EQ(2, vfs_write(fd2, "b", 2));

  // They should have the same vnode.
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/a/file", &stat));
  kino_t a_ino = stat.st_ino;
  KEXPECT_EQ(0, vfs_lstat("vfs_mount_test/b/file", &stat));
  kino_t b_ino = stat.st_ino;
  KEXPECT_EQ(a_ino, b_ino);

  void* addr1_out = NULL;
  KEXPECT_EQ(
      0, do_mmap(NULL, PAGE_SIZE, PROT_ALL, KMAP_PRIVATE, fd1, 0, &addr1_out));
  void* addr2_out = NULL;
  KEXPECT_EQ(
      0, do_mmap(NULL, PAGE_SIZE, PROT_ALL, KMAP_PRIVATE, fd2, 0, &addr2_out));
  KEXPECT_STREQ("a", (char*)addr1_out);
  KEXPECT_STREQ("b", (char*)addr2_out);
  KEXPECT_EQ(0, do_munmap(addr1_out, PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(addr2_out, PAGE_SIZE));
  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(0, vfs_close(fd2));

  // Cleanup.
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/a/file"));
  KEXPECT_EQ(0, vfs_unlink("vfs_mount_test/b/file"));

  // We'll still have vnodes pinned in the block cache from the mmaps (which
  // will cause the unmount to fail if not cleaned up).
  block_cache_clear_unpinned();
  fs_t* unmounted_fs = NULL;
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/a", &unmounted_fs));
  KEXPECT_EQ(0, vfs_unmount_fs("vfs_mount_test/b", &unmounted_fs));

  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/b"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("vfs_mount_test"));
}

void vfs_mount_test(void) {
  KTEST_SUITE_BEGIN("vfs mount test");
  block_cache_clear_unpinned();
  const int orig_cache_size = vfs_cache_size();

  ramfsA = ramfs_create_fs(0);
  ramfsB = ramfs_create_fs(0);

  mmap_same_vnode_test();  // Must be first.
  basic_mount_test();
  dot_dot_test();
  mount_cwd_test();
  rmdir_mount_test();
  chown_chmod_test();
  unmount_busy_test();
  mount_under_mount_test();
  double_mount_test();
  too_many_mounts_test();
  symlink_mount_test();
  rename_mount_test();

  KEXPECT_EQ(orig_cache_size, vfs_cache_size());

  ramfs_destroy_fs(ramfsA);
  ramfs_destroy_fs(ramfsB);
}
