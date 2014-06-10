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
#include "memory/kmalloc.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "vfs/dirent.h"
#include "vfs/cbfs.h"
#include "vfs/mount.h"
#include "vfs/vfs.h"

static fs_t* g_basic_fs = 0x0;

static int basic_file_read_test(fs_t* fs, void* arg, int offset, void* buf,
                                int buflen) {
  KEXPECT_EQ(g_basic_fs, fs);
  KEXPECT_EQ((void*)0x1, arg);
  KEXPECT_EQ(2, offset);
  KEXPECT_EQ(100, buflen);

  kstrcpy(buf, "abcde");
  return 6;
}

static void basic_file_test(fs_t* fs) {
  KTEST_BEGIN("cbfs: basic file test");

  KEXPECT_EQ(0, cbfs_create_file(fs, "file", &basic_file_read_test, (void*)0x1,
                                 VFS_S_IRWXU));
  int fd = vfs_open("cbfs_test_root/file", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_seek(fd, 2, VFS_SEEK_SET));

  char buf[100];
  KEXPECT_EQ(6, vfs_read(fd, buf, 100));
  KEXPECT_STREQ("abcde", buf);

  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("cbfs: basic getdents");
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "file"}}));


  KTEST_BEGIN("cbfs: creating directory over file");
  KEXPECT_EQ(-ENOTDIR, cbfs_create_file(fs, "file/f2", &basic_file_read_test,
                                        0x0, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOTDIR,
             cbfs_create_file(fs, "file/dir/f2", &basic_file_read_test, 0x0,
                              VFS_S_IRWXU));

  KTEST_BEGIN("cbfs: creating over existing file");
  KEXPECT_EQ(-EEXIST, cbfs_create_file(fs, "file", &basic_file_read_test, 0x0,
                                       VFS_S_IRWXU));


  KTEST_BEGIN("cbfs: multi-level directory creation");
  KEXPECT_EQ(0, cbfs_create_file(fs, "dir1/dir2/dir3/f", &basic_file_read_test,
                                 (void*)0x1, VFS_S_IRWXU));
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("cbfs_test_root/dir1", &stat));
  KEXPECT_EQ(VFS_S_IFDIR, stat.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(0, vfs_lstat("cbfs_test_root/dir1/dir2", &stat));
  KEXPECT_EQ(VFS_S_IFDIR, stat.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(0, vfs_lstat("cbfs_test_root/dir1/dir2", &stat));
  KEXPECT_EQ(VFS_S_IFDIR, stat.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(0, vfs_lstat("cbfs_test_root/dir1/dir2/dir3", &stat));
  KEXPECT_EQ(VFS_S_IFDIR, stat.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(0, vfs_lstat("cbfs_test_root/dir1/dir2/dir3/f", &stat));
  KEXPECT_EQ(VFS_S_IFREG, stat.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root/dir1", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dir2"}}));


  KTEST_BEGIN("cbfs: open non-existant files");
  KEXPECT_EQ(-ENOENT, vfs_open("cbfs_test_root/x", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("cbfs_test_root/x/y", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("cbfs_test_root/dir1/y", VFS_O_RDONLY));

  KTEST_BEGIN("cbfs: open non-directory path");
  KEXPECT_EQ(-ENOTDIR, vfs_open("cbfs_test_root/file/y", VFS_O_RDONLY));

  KTEST_BEGIN("cbfs: can't create file with vfs_open");
  KEXPECT_EQ(-EACCES, vfs_open("cbfs_test_root/file1",
                               VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU));

  KTEST_BEGIN("cbfs: can't create file with vfs_mknod");
  KEXPECT_EQ(-EACCES,
             vfs_mknod("cbfs_test_root/file1", VFS_S_IFREG, mkdev(0, 0)));

  KTEST_BEGIN("cbfs: can't create directory with vfs_mkdir()");
  KEXPECT_EQ(-EACCES, vfs_mkdir("cbfs_test_root/dir4", VFS_S_IRWXU));

  KTEST_BEGIN("cbfs: can't remove directory with vfs_rmdir()");
  KEXPECT_EQ(-EACCES, vfs_rmdir("cbfs_test_root/dir1"));

  KTEST_BEGIN("cbfs: can't remove file with vfs_unlink()");
  KEXPECT_EQ(-EACCES, vfs_unlink("cbfs_test_root/file"));
}

void cbfs_test(void) {
  KTEST_SUITE_BEGIN("cbfs");

  KTEST_BEGIN("cbfs test setup");
  fs_t* fs =  cbfs_create();
  vfs_mkdir("cbfs_test_root", VFS_S_IRWXU);
  KEXPECT_EQ(0, vfs_mount_fs("cbfs_test_root", fs));

  g_basic_fs = fs;


  basic_file_test(fs);


  KTEST_BEGIN("cbfs test cleanup");
  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("cbfs_test_root", &unmounted_fs));
  KEXPECT_EQ(fs, unmounted_fs);
  KEXPECT_EQ(0, vfs_rmdir("cbfs_test_root"));
  cbfs_free(fs);
}
