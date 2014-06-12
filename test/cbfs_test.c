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
#include "common/math.h"
#include "memory/kmalloc.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "vfs/dirent.h"
#include "vfs/cbfs.h"
#include "vfs/mount.h"
#include "vfs/vfs.h"

static fs_t* g_basic_fs = 0x0;

#define ENABLE_LARGE_DYNAMIC_TEST 0

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

static void null_lookup_test(fs_t* fs) {
  KTEST_BEGIN("cbfs: unknown vnode with no lookup function");

  vnode_t vnode;
  vfs_vnode_init(&vnode, 999);
  vnode.fs = fs;
  KEXPECT_EQ(-ENOENT, fs->get_vnode(&vnode));
}

static int no_read(fs_t* fs, void* arg, int offset, void* outbuf, int buflen) {
  return 0;
}

static int cbfs_test_lookup(fs_t* fs, void* arg, int vnode,
                            cbfs_inode_t* inode_out) {
  KEXPECT_EQ(0x5, (int)arg);
  if (vnode >= 100 && vnode <= 105) {
    cbfs_inode_create_file(inode_out, vnode, &no_read, 0, 1, 2, VFS_S_IRWXU);
    return 0;
  } else if (vnode == 106) {
    return -ENOMEM;
  }
  return -ENOENT;
}

static void lookup_function_test(void) {
  KTEST_BEGIN("cbfs: vnode lookup function");
  fs_t* fs =  cbfs_create(cbfs_test_lookup, (void*)0x5);
  KEXPECT_EQ(0, vfs_mount_fs("cbfs_test_root", fs));


  vnode_t vnode;
  vfs_vnode_init(&vnode, 99);
  vnode.fs = fs;
  KEXPECT_EQ(-ENOENT, fs->get_vnode(&vnode));

  vfs_vnode_init(&vnode, 102);
  vnode.fs = fs;
  KEXPECT_EQ(0, fs->get_vnode(&vnode));
  KEXPECT_EQ(VNODE_REGULAR, vnode.type);
  KEXPECT_EQ(1, vnode.uid);
  KEXPECT_EQ(2, vnode.gid);
  KEXPECT_EQ(VFS_S_IRWXU, vnode.mode);

  vfs_vnode_init(&vnode, 106);
  vnode.fs = fs;
  KEXPECT_EQ(-ENOMEM, fs->get_vnode(&vnode));

  vfs_vnode_init(&vnode, 107);
  vnode.fs = fs;
  KEXPECT_EQ(-ENOENT, fs->get_vnode(&vnode));

  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("cbfs_test_root", &unmounted_fs));
}

static int dynamic_dir_getdents(fs_t* fs, void* arg, int offset,
                                list_t* list_out, void* buf, int buflen) {
  if ((int)arg == 1) {
    // Mode 1: create several file entries and return them one by one.
    if (offset < 4) {
      char name[100];
      ksprintf(name, "f%d", offset);
      const int entry_size = cbfs_entry_size(name);
      if (entry_size > buflen) return -ENOMEM;
      cbfs_create_entry((cbfs_entry_t*)buf, name, 100 + offset);
      list_push(list_out, &((cbfs_entry_t*)buf)->link);
    }
    return 0;
  } else if ((int) arg == 2) {
    // Mode 2: as many files as we can in the given buffer.
    int fileidx = offset;
    while (fileidx < 1000) {
      char name[100];
      ksprintf(name, "file%d", fileidx);
      const int entry_size = cbfs_entry_size(name);
      if (entry_size > buflen) break;

      cbfs_entry_t* entry = (cbfs_entry_t*)buf;
      cbfs_create_entry(entry, name, 100);
      list_push(list_out, &entry->link);

      buf += entry_size;
      buflen -= entry_size;
      fileidx++;
    }
    if (fileidx == offset && fileidx < 1000) return -ENOMEM;
    return 0;
  } else if ((int) arg == 3) {
    // Mode 3: return an error
    return -EIO;
  }

  return 0;
}

static void dynamic_directory_test(void) {
  KTEST_BEGIN("cbfs: dynamic directory");
  fs_t* fs =  cbfs_create(cbfs_test_lookup, (void*)0x5);
  KEXPECT_EQ(0, vfs_mount_fs("cbfs_test_root", fs));

  KEXPECT_EQ(0, cbfs_create_directory(fs, "dir1", &dynamic_dir_getdents,
                                      (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dir1"}}));

  KEXPECT_EQ(0, compare_dirents_p("cbfs_test_root/dir1", 6,
                                  (edirent_t[]) {{-1, "."},
                                                 {-1, ".."},
                                                 {100, "f0"},
                                                 {101, "f1"},
                                                 {102, "f2"},
                                                 {103, "f3"}}));

  if (ENABLE_LARGE_DYNAMIC_TEST) {
    KTEST_BEGIN("cbfs: dynamic directory (many entries)");
    KEXPECT_EQ(0, cbfs_create_directory(fs, "dir2", &dynamic_dir_getdents,
                                        (void*)2, VFS_S_IRWXU));
    edirent_t many_expected[1002];
    const int kNamesBufSize = 20000;
    char namesbuf[kNamesBufSize];
    char* cname = namesbuf;
    for (int i = 0; i < 1000; i++) {
      ksprintf(cname, "file%d", i);
      many_expected[i].vnode = 100;
      many_expected[i].name = cname;
      cname += kstrlen(cname) + 1;
    }
    many_expected[1000].vnode = -1;
    many_expected[1000].name = ".";
    many_expected[1001].vnode = -1;
    many_expected[1001].name = "..";
    KEXPECT_EQ(0,
               compare_dirents_p("cbfs_test_root/dir2", 1002, many_expected));
  }

  KTEST_BEGIN("cbfs: dynamic directory getdents error");
  KEXPECT_EQ(0, cbfs_create_directory(fs, "dir3", &dynamic_dir_getdents,
                                      (void*)3, VFS_S_IRWXU));

  int fd = vfs_open("cbfs_test_root/dir3", VFS_O_RDONLY);
  char tmp[100];
  KEXPECT_EQ(-EIO, vfs_getdents(fd, (dirent_t*)tmp, 100));
  vfs_close(fd);

  KTEST_BEGIN("cbfs: dynamic directory parent directory creation");
  KEXPECT_EQ(0,
             cbfs_create_directory(fs, "dir4/dirA/dirB", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root/dir4", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dirA"}}));
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root/dir4/dirA", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dirB"}}));
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root/dir4/dirA/.", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dirB"}}));
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root/dir4/dirA/..", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dirA"}}));
  KEXPECT_EQ(0, compare_dirents_p(
                    "cbfs_test_root/dir4/dirA/dirB/../../dirA", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "dirB"}}));
  KEXPECT_EQ(0, compare_dirents_p("cbfs_test_root/dir4/dirA/dirB", 6,
                                  (edirent_t[]) {{-1, "."},
                                                 {-1, ".."},
                                                 {100, "f0"},
                                                 {101, "f1"},
                                                 {102, "f2"},
                                                 {103, "f3"}}));
  KEXPECT_EQ(0, compare_dirents_p("cbfs_test_root/dir4/dirA/dirB/.", 6,
                                  (edirent_t[]) {{-1, "."},
                                                 {-1, ".."},
                                                 {100, "f0"},
                                                 {101, "f1"},
                                                 {102, "f2"},
                                                 {103, "f3"}}));

  KTEST_BEGIN("cbfs: dynamic directory creation over directory");
  KEXPECT_EQ(-EEXIST, cbfs_create_directory(fs, "dir4", &dynamic_dir_getdents,
                                            (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST,
             cbfs_create_directory(fs, "dir4/dirA", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST,
             cbfs_create_directory(fs, "dir4/dirA/dirB", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));

  KTEST_BEGIN("cbfs: dynamic directory creation over file");
  KEXPECT_EQ(0, cbfs_create_file(fs, "file", &basic_file_read_test, (void*)0x1,
                                 VFS_S_IRWXU));
  KEXPECT_EQ(0, cbfs_create_file(fs, "dir4/file", &basic_file_read_test,
                                 (void*)0x1, VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST, cbfs_create_directory(fs, "file", &dynamic_dir_getdents,
                                            (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST,
             cbfs_create_directory(fs, "dir4/file", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));

  KTEST_BEGIN("cbfs: dynamic directory creation over file");
  KEXPECT_EQ(-ENOTDIR,
             cbfs_create_directory(fs, "file/dirC", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOTDIR,
             cbfs_create_directory(fs, "file/dirC/dirD", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOTDIR,
             cbfs_create_directory(fs, "dir4/file/dirC", &dynamic_dir_getdents,
                                   (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOTDIR, cbfs_create_directory(fs, "dir4/file/dirC/dirD",
                                             &dynamic_dir_getdents, (void*)1,
                                             VFS_S_IRWXU));

  KTEST_BEGIN("cbfs: dynamic directory with static entries");
  KEXPECT_EQ(0, cbfs_create_directory(fs, "dir5", &dynamic_dir_getdents,
                                      (void*)1, VFS_S_IRWXU));
  KEXPECT_EQ(0, compare_dirents_p("cbfs_test_root/dir5", 6,
                                  (edirent_t[]) {{-1, "."},
                                                 {-1, ".."},
                                                 {100, "f0"},
                                                 {101, "f1"},
                                                 {102, "f2"},
                                                 {103, "f3"}}));
  KEXPECT_EQ(0, cbfs_create_file(fs, "dir5/file", &basic_file_read_test,
                                 (void*)0x1, VFS_S_IRWXU));
  KEXPECT_EQ(0, compare_dirents_p("cbfs_test_root/dir5", 7,
                                  (edirent_t[]) {{-1, "."},
                                                 {-1, ".."},
                                                 {100, "f0"},
                                                 {101, "f1"},
                                                 {102, "f2"},
                                                 {103, "f3"},
                                                 {-1, "file"}}));

  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("cbfs_test_root", &unmounted_fs));
}

void cbfs_test(void) {
  KTEST_SUITE_BEGIN("cbfs");

  KTEST_BEGIN("cbfs test setup");
  fs_t* fs =  cbfs_create(0x0, 0x0);
  vfs_mkdir("cbfs_test_root", VFS_S_IRWXU);
  KEXPECT_EQ(0, vfs_mount_fs("cbfs_test_root", fs));

  g_basic_fs = fs;


  basic_file_test(fs);
  null_lookup_test(fs);

  lookup_function_test();
  dynamic_directory_test();


  KTEST_BEGIN("cbfs test cleanup");
  fs_t* unmounted_fs = 0x0;
  KEXPECT_EQ(0, vfs_unmount_fs("cbfs_test_root", &unmounted_fs));
  KEXPECT_EQ(fs, unmounted_fs);
  KEXPECT_EQ(0, vfs_rmdir("cbfs_test_root"));
  cbfs_free(fs);
}
