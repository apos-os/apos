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

#include <stdalign.h>
#include <stdarg.h>
#include <stdint.h>

#include "common/arch-config.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/math.h"
#include "dev/dev.h"
#include "dev/ramdisk/ramdisk.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/page_alloc.h"
#include "proc/exec.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread-internal.h"
#include "proc/limit.h"
#include "proc/signal/signal.h"
#include "proc/wait.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "test/ktest.h"
#include "test/test_params.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/vfs/dirent.h"
#include "vfs/fs.h"
#include "vfs/pipe.h"
#include "vfs/poll.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs.h"
#include "vfs/vfs_internal.h"
#include "vfs/vfs_test_util.h"

// Increase this to make thread safety tests run longer.
#define THREAD_SAFETY_MULTIPLIER 1

#define TRUNCATE_MANY_LARGE_FILES_TEST 0

#define EXPECT_VNODE_REFCOUNT(count, path) \
    KEXPECT_EQ((count), vfs_get_vnode_refcount_for_path(path))

#define RWX "rwxrwxrwx"

// TODO(aoates): put this in some sort of proper test context data structure.
static int g_orig_root_vnode_refcount = -1;

static void create_file_with_data(const char* path, const char* data) {
  const int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR, 0);
  KASSERT(fd >= 0);
  const int result = vfs_write(fd, data, kstrlen(data));
  KASSERT(result == kstrlen(data));
  vfs_close(fd);
}

// Fill the buffer with an interesting pattern.
static void fill_with_pattern(uint32_t seed, void* buf, int len) {
  uint32_t val = seed;
  for (int i = 0; i < len; ++i) {
    ((uint8_t*)buf)[i] = (uint8_t)val;
    val = fnv_hash(val);
    KASSERT(val != 0);
  }
}

static int get_file_refcount(int fd) {
  file_t* file;
  int result = lookup_fd(fd, &file);
  if (result < 0) return result;
  result = refcount_get(&file->refcount) - 1;
  file_unref(file);
  return result;
}

typedef struct {
  const char* path;
  // TODO(aoates): use spinlock, mutex, or notification.
  bool done;
} chaos_args_t;

// A thread that just tries to get mutexes locked to force other threads to
// block at inopportune times.
static void* chaos_helper(void* arg) {
  const chaos_args_t* args = (const chaos_args_t*)arg;
  apos_stat_t stat;
  int result;
  do {
    result = vfs_stat(args->path, &stat);
  } while (result == -EINJECTEDFAULT);
  KEXPECT_EQ(0, result);
  const apos_ino_t dir_ino = stat.st_ino;
  vnode_t* dir_vnode = vfs_get(vfs_get_root_fs(), dir_ino);
  while (!args->done) {
    kmutex_lock(&dir_vnode->mutex);
    scheduler_yield();
    kmutex_unlock(&dir_vnode->mutex);
  }
  vfs_put(dir_vnode);
  return NULL;
}

static void dev_test(void) {
  KTEST_BEGIN("device numbering test");
  apos_dev_t dev = kmakedev(0, 0);
  KEXPECT_EQ(0, kmajor(dev));
  KEXPECT_EQ(0, kminor(dev));

  dev = kmakedev(0, 5);
  KEXPECT_EQ(0, kmajor(dev));
  KEXPECT_EQ(5, kminor(dev));

  dev = kmakedev(5, 0);
  KEXPECT_EQ(5, kmajor(dev));
  KEXPECT_EQ(0, kminor(dev));

  dev = kmakedev(UINT8_MAX, 0);
  KEXPECT_EQ(UINT8_MAX, kmajor(dev));
  KEXPECT_EQ(0, kminor(dev));

  dev = kmakedev(0, UINT8_MAX);
  KEXPECT_EQ(0, kmajor(dev));
  KEXPECT_EQ(UINT8_MAX, kminor(dev));

  dev = kmakedev(UINT16_MAX, 0);
  KEXPECT_EQ(UINT16_MAX, kmajor(dev));
  KEXPECT_EQ(0, kminor(dev));

  dev = kmakedev(0, UINT16_MAX);
  KEXPECT_EQ(0, kmajor(dev));
  KEXPECT_EQ(UINT16_MAX, kminor(dev));

  dev = kmakedev(UINT16_MAX, UINT16_MAX - 1);
  KEXPECT_EQ(UINT16_MAX, kmajor(dev));
  KEXPECT_EQ(UINT16_MAX - 1, kminor(dev));

  dev = kmakedev(UINT16_MAX - 1, UINT16_MAX);
  KEXPECT_EQ(UINT16_MAX - 1, kmajor(dev));
  KEXPECT_EQ(UINT16_MAX, kminor(dev));

  dev = kmakedev(UINT16_MAX, UINT16_MAX);
  KEXPECT_EQ(UINT16_MAX, kmajor(dev));
  KEXPECT_EQ(UINT16_MAX, kminor(dev));

  dev = kmakedev(UINT16_MAX, UINT16_MAX);
  KEXPECT_EQ(UINT16_MAX, kmajor(dev));
  KEXPECT_EQ(UINT16_MAX, kminor(dev));
}

// Test that we correctly refcount parent directories when calling vfs_open().
static void open_parent_refcount_test(void) {
  KTEST_BEGIN("vfs_open(): parent refcount test");
  KEXPECT_EQ(0, vfs_mkdir("/ref_dir1", 0));
  KEXPECT_EQ(0, vfs_mkdir("/ref_dir1/dir2", 0));

  const int fd1 = vfs_open("/ref_dir1/dir2/test1", VFS_O_CREAT | VFS_O_RDWR, 0);
  KEXPECT_GE(fd1, 0);

  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(1, "/ref_dir1/dir2/test1");

  const int fd2 = vfs_open("/ref_dir1/dir2/test1", VFS_O_CREAT | VFS_O_RDWR, 0);
  KEXPECT_GE(fd2, 0);

  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(2, "/ref_dir1/dir2/test1");

  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(0, vfs_close(fd2));

  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2/test1");

  // Clean up.
  vfs_unlink("/ref_dir1/dir2/test1");
  vfs_rmdir("/ref_dir1/dir2");
  vfs_rmdir("/ref_dir1");
}

// Test calling vfs_open() on a directory.
static void open_dir_test(void) {
  KTEST_BEGIN("vfs_open(): open directory (read-only)");
  KEXPECT_EQ(0, vfs_mkdir("/dir1", 0));
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  int fd = vfs_open("/dir1", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  KTEST_BEGIN("vfs_open(): open directory (RW/write-only)");
  KEXPECT_EQ(-EISDIR, vfs_open("/dir1", VFS_O_WRONLY));
  KEXPECT_EQ(-EISDIR, vfs_open("/dir1", VFS_O_RDWR));

  KTEST_BEGIN("vfs_open(): open root directory");
  fd = vfs_open("/", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  // Clean up.
  EXPECT_VNODE_REFCOUNT(0, "/dir1");
  KEXPECT_EQ(0, vfs_rmdir("/dir1"));
}

static void open_test(void) {
  KTEST_BEGIN("vfs_open() test");

  vfs_log_cache();
  KEXPECT_EQ(-ENOENT, vfs_open("/test1", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(-ENOENT, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(0, vfs_open("/test1", VFS_O_CREAT | VFS_O_RDWR, 0));
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(1, vfs_open("/test1", VFS_O_CREAT | VFS_O_RDWR, 0));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(2, vfs_open("/test2", VFS_O_CREAT | VFS_O_RDWR, 0));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  EXPECT_VNODE_REFCOUNT(1, "/test2");
  vfs_log_cache();

  KEXPECT_EQ(3, vfs_open("/test1", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(3, "/test1");
  EXPECT_VNODE_REFCOUNT(1, "/test2");
  vfs_log_cache();

  KTEST_BEGIN("vfs_close() test");
  KEXPECT_EQ(-EBADF, vfs_close(-10));
  KEXPECT_EQ(-EBADF, vfs_close(10000000));
  KEXPECT_EQ(-EBADF, vfs_close(5));

  KEXPECT_EQ(0, vfs_close(1));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  EXPECT_VNODE_REFCOUNT(1, "/test2");
  vfs_log_cache();

  // Make sure we reuse the fd.
  KEXPECT_EQ(1, vfs_open("/test3", VFS_O_CREAT | VFS_O_RDWR, 0));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  EXPECT_VNODE_REFCOUNT(1, "/test2");
  EXPECT_VNODE_REFCOUNT(1, "/test3");
  vfs_log_cache();

  // Close everything else.
  KEXPECT_EQ(0, vfs_close(3));
  vfs_log_cache();
  KEXPECT_EQ(0, vfs_close(2));
  vfs_log_cache();
  KEXPECT_EQ(0, vfs_close(0));
  vfs_log_cache();

  EXPECT_VNODE_REFCOUNT(0, "/test1");
  EXPECT_VNODE_REFCOUNT(0, "/test2");

  KTEST_BEGIN("re-vfs_open() test");
  KEXPECT_EQ(0, vfs_open("/test1", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  vfs_log_cache();

  // Close everything.
  KEXPECT_EQ(0, vfs_close(0));
  KEXPECT_EQ(0, vfs_close(1));

  // TODO(aoates): test in subdirectories once mkdir works
  KTEST_BEGIN("vfs_open() w/ directories test");
  KEXPECT_EQ(-EISDIR, vfs_open("/", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  KEXPECT_EQ(-ENOTDIR, vfs_open("/test1/test2", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  KEXPECT_EQ(-ENOTDIR, vfs_open("/test1/test2", VFS_O_CREAT | VFS_O_RDWR, 0));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");

  open_parent_refcount_test();
  open_dir_test();

  KTEST_BEGIN("vfs_open(): invalid mode");
  KEXPECT_EQ(-EINVAL, vfs_open("/test1", VFS_O_RDWR | VFS_O_WRONLY));

  KTEST_BEGIN("vfs_open(): empty path");
  KEXPECT_EQ(-ENOENT, vfs_open("", VFS_O_RDWR));

  // Clean up.
  KEXPECT_EQ(0, vfs_unlink("/test1"));
  KEXPECT_EQ(0, vfs_unlink("/test2"));
  KEXPECT_EQ(0, vfs_unlink("/test3"));
}

static void mkdir_test(void) {
  KTEST_BEGIN("vfs_mkdir() test");

  // Make sure we have some normal files around.
  const int test1_fd = vfs_open("/test1", VFS_O_CREAT | VFS_O_RDWR, 0);
  KEXPECT_GE(test1_fd, 0);

  KEXPECT_EQ(-EEXIST, vfs_mkdir("/", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/test1", 0));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");

  KEXPECT_EQ(-ENOTDIR, vfs_mkdir("/test1/dir1", 0));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");

  KTEST_BEGIN("regular mkdir()");
  KEXPECT_EQ(0, vfs_mkdir("/dir1", 0));
  KEXPECT_EQ(0, vfs_mkdir("/dir2", 0));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir2", 0));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KTEST_BEGIN("nested mkdir()");
  KEXPECT_EQ(-ENOENT, vfs_mkdir("/dir1/dir1a/dir1b", 0));
  KEXPECT_EQ(0, vfs_mkdir("/dir1/dir1a", 0));
  KEXPECT_EQ(0, vfs_mkdir("/dir1/dir1a/dir1b", 0));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a/dir1b");

  // TODO(aoates): better testing for . and ...
  // TODO(aoates): test '.' and '..' at the end of paths
  KTEST_BEGIN("crappy '.' and '..' tests");
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/.", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/..", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/./dir1", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/../dir1", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/../../../dir1", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1/./././dir1a", 0));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1/../dir2/../dir1/./dir1a/dir1b/../dir1b", 0));

  // TODO(aoates): create files in the directories, open them
  // TODO(aoates): test '.' and '..' links!
  // TODO(aoates): test multiple slashes and traling slashes
  // TODO(aoates): test unlink()'ing a directory
  // TODO(aoates): you can't unlink '.' or '..'

  KTEST_BEGIN("rmdir(): directory or path doesn't exist");
  KEXPECT_EQ(-ENOENT, vfs_rmdir("/boo"));
  KEXPECT_EQ(-ENOENT, vfs_rmdir("/dir1/boo"));
  KEXPECT_EQ(-ENOENT, vfs_rmdir("/boo/boo2"));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KTEST_BEGIN("rmdir(): not a directory");
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("/test1"));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  // TODO(aoates): test nested not-a-dir

  KTEST_BEGIN("rmdir(): not a directory (chardev file)");
  KEXPECT_EQ(0, vfs_mknod("chr_file", VFS_S_IFCHR, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("chr_file"));
  KEXPECT_EQ(0, vfs_unlink("chr_file"));

  KTEST_BEGIN("rmdir(): not a directory (blockdev file)");
  KEXPECT_EQ(0, vfs_mknod("blk_file", VFS_S_IFBLK, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("blk_file"));
  KEXPECT_EQ(0, vfs_unlink("blk_file"));

  KTEST_BEGIN("rmdir(): not a directory (symlink)");
  KEXPECT_EQ(0, vfs_symlink("/dir1", "dir_link"));
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("dir_link"));
  KEXPECT_EQ(0, vfs_unlink("dir_link"));

  KTEST_BEGIN("rmdir(): not a directory (FIFO)");
  KEXPECT_EQ(0, vfs_mknod("_rmdir_fifo", VFS_S_IFIFO, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("_rmdir_fifo"));
  KEXPECT_EQ(0, vfs_unlink("_rmdir_fifo"));

  KTEST_BEGIN("rmdir(): root directory");
  KEXPECT_EQ(-EPERM, vfs_rmdir("/"));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");

  KTEST_BEGIN("rmdir(): invalid paths");
  KEXPECT_EQ(-EINVAL, vfs_rmdir("/dir1/dir1a/."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/dir1a/dir1b/.."));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a/dir1b");

  KTEST_BEGIN("rmdir(): not empty");
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/dir1a"));
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  // Actually test it (and cleanup the directories we created).
  KTEST_BEGIN("rmdir(): working");
  KEXPECT_EQ(-0, vfs_rmdir("/dir2"));
  KEXPECT_EQ(-0, vfs_rmdir("/dir1/dir1a/.././dir1a/dir1b"));
  KEXPECT_EQ(-0, vfs_rmdir("/dir1/dir1a/"));
  KEXPECT_EQ(-0, vfs_rmdir("///dir1//"));

  // Should still fail even though it's empty.
  KEXPECT_EQ(-EPERM, vfs_rmdir("/"));

  KTEST_BEGIN("mkdir(): link count");
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent", VFS_S_IRWXU));
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(2, stat.st_nlink);

  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(3, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/A", &stat));
  KEXPECT_EQ(2, stat.st_nlink);

  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(3, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/A", &stat));
  KEXPECT_EQ(3, stat.st_nlink);

  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/C", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(4, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/C", &stat));
  KEXPECT_EQ(2, stat.st_nlink);

  KEXPECT_EQ(-EEXIST, vfs_mkdir("_mkdir_parent/A", VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("_mkdir_parent/A/B", VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("_mkdir_parent/C", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(4, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/A", &stat));
  KEXPECT_EQ(3, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/C", &stat));
  KEXPECT_EQ(2, stat.st_nlink);


  KTEST_BEGIN("rmdir(): link count");
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("_mkdir_parent"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("_mkdir_parent/A"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("_mkdir_parent/A/.."));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(4, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/A", &stat));
  KEXPECT_EQ(3, stat.st_nlink);

  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B"));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(4, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/A", &stat));
  KEXPECT_EQ(2, stat.st_nlink);

  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A"));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(3, stat.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent/C", &stat));
  KEXPECT_EQ(2, stat.st_nlink);

  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/C"));
  KEXPECT_EQ(0, vfs_stat("_mkdir_parent", &stat));
  KEXPECT_EQ(2, stat.st_nlink);

  KTEST_BEGIN("mkdir(): deep directory tree test");
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B/C", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B/C/D", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B/C/D/E", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B/C/D/E/F", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_mkdir_parent/A/B/C/D/E/F/G", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B/C/D/E/F/G"));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B/C/D/E/F"));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B/C/D/E"));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B/C/D"));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B/C"));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A/B"));
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent/A"));

  // Cleanup.
  KEXPECT_EQ(0, vfs_rmdir("_mkdir_parent"));
  vfs_close(test1_fd);
  KEXPECT_EQ(0, vfs_unlink("/test1"));
}

// Test repeatedly opening and closing a file to make sure that we reclaim FDs
// and file table entries correctly.
static void file_table_reclaim_test(void) {
  KTEST_BEGIN("file table reclaim test");
  const char kTestDir[] = "/reclaim_test/";
  const char kTestFile[] = "/reclaim_test/test1";
  KEXPECT_EQ(0, vfs_mkdir(kTestDir, 0));
  int files_opened = 0;
  for (int i = 0; i < VFS_MAX_FILES * 2; ++i) {
    const int fd = vfs_open(kTestFile, VFS_O_CREAT | VFS_O_RDWR, 0);
    if (fd < 0) {
      KEXPECT_GE(fd, 0);
      break;
    }
    files_opened++;
    if (vfs_get_vnode_refcount_for_path(kTestFile) != 1) {
      EXPECT_VNODE_REFCOUNT(1, kTestFile);
    }
    vfs_close(fd);
    if (vfs_get_vnode_refcount_for_path(kTestFile) != 0) {
      EXPECT_VNODE_REFCOUNT(0, kTestFile);
    }
  }
  KEXPECT_EQ(VFS_MAX_FILES * 2, files_opened);

  // Clean up.
  KEXPECT_EQ(0, vfs_unlink("/reclaim_test/test1"));
  KEXPECT_EQ(0, vfs_rmdir("/reclaim_test"));
}

// Test thread-safety of allocating file descriptors and file table entries by
// repeatedly opening and closing a file.
#define THREAD_SAFETY_TEST_ITERS (100 * THREAD_SAFETY_MULTIPLIER)
#define THREAD_SAFETY_TEST_THREADS 10

typedef struct {
  kmutex_t mu;

  // How many threads have a given FD open right now.
  int fds_open[PROC_MAX_FDS];

  // How many threads have ever opened each FD.
  int fds_total_count[PROC_MAX_FDS];
} thread_safety_test_t;

static void* vfs_open_thread_safety_test_func(void* arg) {
  thread_safety_test_t* test = (thread_safety_test_t*)arg;
  for (int i = 0; i < THREAD_SAFETY_TEST_ITERS; ++i) {
    int fd = vfs_open("/thread_safety_test/a/./b/../b/thread_safety_test_file",
                      VFS_O_CREAT | VFS_O_RDWR, 0);
    KASSERT(fd >= 0);

    kmutex_lock(&test->mu);
    KASSERT(test->fds_open[fd] == 0);
    test->fds_open[fd] = 1;
    test->fds_total_count[fd]++;
    kmutex_unlock(&test->mu);

    vfs_close(fd);
    kmutex_lock(&test->mu);
    KASSERT(test->fds_open[fd] == 1);
    test->fds_open[fd] = 0;
    kmutex_unlock(&test->mu);
  }
  return 0;
}

static void vfs_open_thread_safety_test(void) {
  KTEST_BEGIN("vfs_open() thread safety test");
  kthread_t threads[THREAD_SAFETY_TEST_THREADS];

  // Set things up.
  KASSERT(vfs_mkdir("/thread_safety_test", 0) == 0);
  KASSERT(vfs_mkdir("/thread_safety_test/a", 0) == 0);
  KASSERT(vfs_mkdir("/thread_safety_test/a/b", 0) == 0);

  thread_safety_test_t test;
  kmutex_init(&test.mu);
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    test.fds_open[i] = test.fds_total_count[i] = 0;
  }

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    KASSERT(proc_thread_create(&threads[i], &vfs_open_thread_safety_test_func,
                               &test) == 0);
  }

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  int total_open = 0;
  int total = 0;
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    total_open += test.fds_open[i];
    total += test.fds_total_count[i];
  }

  KEXPECT_EQ(0, total_open);
  KEXPECT_EQ(THREAD_SAFETY_TEST_THREADS * THREAD_SAFETY_TEST_ITERS, total);

  // Clean up
  vfs_unlink("/thread_safety_test/a/b/thread_safety_test_file");
  vfs_rmdir("/thread_safety_test/a/b");
  vfs_rmdir("/thread_safety_test/a");
  vfs_rmdir("/thread_safety_test");
}

static void* vfs_open_create_race_test_func(void* arg) {
  for (int i = 0; i < THREAD_SAFETY_TEST_ITERS / 10; ++i) {
    if (i % 3 == 0) scheduler_yield();
    int fd = vfs_open("thread_safety_test/file", VFS_O_CREAT | VFS_O_RDWR, 0);
    KEXPECT_GE(fd, 0);
    KEXPECT_EQ(0, vfs_close(fd));
    // Could fail if other thread deletes first.
    vfs_unlink("thread_safety_test/file");
  }
  return 0;
}

static void vfs_open_create_race_test(void) {
  KTEST_BEGIN("vfs_open() creation race test");
  kthread_t threads[THREAD_SAFETY_TEST_THREADS];
  kthread_t chaos_thread;

  // Set things up.
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test", 0));

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[i],
                                     &vfs_open_create_race_test_func, NULL));
  }
  chaos_args_t chaos_args;
  chaos_args.path = "thread_safety_test";
  chaos_args.done = false;
  KEXPECT_EQ(0, proc_thread_create(&chaos_thread, &chaos_helper, &chaos_args));

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    kthread_join(threads[i]);
  }
  chaos_args.done = true;
  kthread_join(chaos_thread);

  // Clean up
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test"));
}

static void* vfs_get_fifo_socket_test_func(void* arg) {
  const char* path = (const char*)arg;
  vnode_t* vnode = NULL;
  KEXPECT_EQ(0, lookup_existing_path(path, lookup_opt(false), &vnode));
  if (!vnode) return 0x0;
  fs_t* fs = vnode->fs;
  apos_ino_t vnode_num = vnode->num;
  vfs_put(vnode);
  for (int i = 0; i < THREAD_SAFETY_TEST_ITERS / 10; ++i) {
    vnode = vfs_get(fs, vnode_num);
    KEXPECT_NE(NULL, vnode);
    KEXPECT_EQ(vnode_num, vnode->num);
    vfs_put(vnode);
  }
  return 0;
}

static void* vfs_open_fifo_socket_test_func(void* arg) {
  const char* path = (const char*)arg;
  for (int i = 0; i < THREAD_SAFETY_TEST_ITERS / 10; ++i) {
    int fd = vfs_open(path, VFS_O_RDONLY | VFS_O_NONBLOCK, 0);
    if (fd == 0) {
      KEXPECT_EQ(0, vfs_close(fd));
    } else {
      KEXPECT_EQ(-EOPNOTSUPP, fd);  // Can't open sockets.
    }
  }
  return 0;
}

// Test for vfs_get() and vfs_open() which have custom logic for FIFOs and
// sockets.
static void vfs_open_get_fifo_socket_test(void) {
  KTEST_BEGIN("vfs_get(): FIFO get race test ");
  const int kThreads = 2;  // Only two threads to exercise 0->1 and 1->0 cases.
  kthread_t threads[kThreads];

  // Set things up.
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test", 0));
  KEXPECT_EQ(0,
             vfs_mknod("thread_safety_test/fifo", VFS_S_IFIFO, kmakedev(0, 0)));

  for (int i = 0; i < kThreads; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&threads[i], &vfs_get_fifo_socket_test_func,
                                  "thread_safety_test/fifo"));
  }

  for (int i = 0; i < kThreads; ++i) {
    kthread_join(threads[i]);
  }

  KTEST_BEGIN("vfs_get(): socket get race test ");
  vnode_t* vnode = NULL;
  KEXPECT_EQ(0,
             vfs_mksocket("thread_safety_test/socket", VFS_S_IFSOCK, &vnode));
  vfs_put(vnode);

  for (int i = 0; i < kThreads; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&threads[i], &vfs_get_fifo_socket_test_func,
                                  "thread_safety_test/socket"));
  }
  for (int i = 0; i < kThreads; ++i) {
    kthread_join(threads[i]);
  }


  KTEST_BEGIN("vfs_open(): FIFO open race test ");
  for (int i = 0; i < kThreads; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&threads[i], &vfs_open_fifo_socket_test_func,
                                  "thread_safety_test/fifo"));
  }
  for (int i = 0; i < kThreads; ++i) {
    kthread_join(threads[i]);
  }

  KTEST_BEGIN("vfs_open(): socket open race test ");
  for (int i = 0; i < kThreads; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&threads[i], &vfs_open_fifo_socket_test_func,
                                  "thread_safety_test/socket"));
  }
  for (int i = 0; i < kThreads; ++i) {
    kthread_join(threads[i]);
  }

  // Clean up
  KEXPECT_EQ(0, vfs_unlink("thread_safety_test/fifo"));
  KEXPECT_EQ(0, vfs_unlink("thread_safety_test/socket"));
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test"));
}

static void unlink_test(void) {
  KTEST_BEGIN("vfs_unlink(): basic test");
  int fd = vfs_open("/unlink", VFS_O_CREAT | VFS_O_RDWR, 0);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("/unlink"));
  KEXPECT_EQ(-ENOENT, vfs_open("/unlink", VFS_O_RDWR));

  KTEST_BEGIN("vfs_unlink(): non-existent file");
  KEXPECT_EQ(-ENOENT, vfs_unlink("/doesnt_exist"));

  KTEST_BEGIN("vfs_unlink(): in a directory");
  vfs_mkdir("/unlink", 0);
  vfs_mkdir("/unlink/a", 0);
  fd = vfs_open("/unlink/a/file", VFS_O_CREAT | VFS_O_RDWR, 0);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("/unlink/./a/../../unlink/a/./file"));
  KEXPECT_EQ(-ENOENT, vfs_unlink("/unlink/./a/../../unlink/a/./file"));

  KTEST_BEGIN("vfs_unlink(): non-directory in path");
  fd = vfs_open("/unlink/a/file", VFS_O_CREAT | VFS_O_RDWR, 0);
  vfs_close(fd);
  KEXPECT_EQ(-ENOTDIR, vfs_unlink("/unlink/a/file/in_file"));
  KEXPECT_EQ(0, vfs_unlink("/unlink/a/file")); // Clean up.

  KTEST_BEGIN("vfs_unlink(): unlinking directory");
  KEXPECT_EQ(-EISDIR, vfs_unlink("/unlink/a"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("/"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("/."));
  KEXPECT_EQ(-EISDIR, vfs_unlink("/.."));
  KEXPECT_EQ(-EISDIR, vfs_unlink("/unlink/a/"));
  KEXPECT_EQ(-EISDIR, vfs_unlink("/unlink/a/."));
  KEXPECT_EQ(-EISDIR, vfs_unlink("/unlink/a/.."));

  // Clean up.
  vfs_rmdir("/unlink/a");
  vfs_rmdir("/unlink");
}

static void* unlink_race_test_func1(void* arg) {
  for (int i = 0; i < THREAD_SAFETY_TEST_ITERS / 10; ++i) {
    // Alternate creating the file with open() or link() for variety.
    if (i % 2 == 0) {
      int fd =
          vfs_open("thread_safety_test/file2", VFS_O_CREAT | VFS_O_RDWR, 0);
      KEXPECT_GE(fd, 0);
      KEXPECT_EQ(0, vfs_close(fd));
    } else {
      KEXPECT_EQ(
          0, vfs_link("thread_safety_test/file1", "thread_safety_test/file2"));
    }
    if (i % 3 == 0) scheduler_yield();
    // Could fail if other thread deletes first.
    int result = vfs_unlink("thread_safety_test/file2");
    if (result < 0) {
      KEXPECT_EQ(-ENOENT, result);
    }
  }
  return 0;
}

static void* unlink_race_test_func2(void* arg) {
  // TODO(aoates): use lock, atomic, or notification.
  bool* done = (bool*)arg;
  while (!*done) {
    int result = vfs_unlink("thread_safety_test/file2");
    if (result < 0) {
      KEXPECT_EQ(-ENOENT, result);
    }
    scheduler_yield();
  }
  return 0;
}

static void unlink_race_test(void) {
  KTEST_BEGIN("vfs_unlink() race test");
  kthread_t creating_thread, chaos_thread;
  kthread_t unlink_threads[THREAD_SAFETY_TEST_THREADS];

  // Set things up.
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test", 0));
  create_file("thread_safety_test/file1", "rwxrwxrwx");

  chaos_args_t chaos_args;
  chaos_args.path = "thread_safety_test";
  chaos_args.done = false;
  KEXPECT_EQ(0, proc_thread_create(&chaos_thread, &chaos_helper, &chaos_args));

  KEXPECT_EQ(
      0, proc_thread_create(&creating_thread, &unlink_race_test_func1, NULL));

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&unlink_threads[i], &unlink_race_test_func2,
                                  &chaos_args.done));
  }

  kthread_join(creating_thread);
  chaos_args.done = true;
  kthread_join(chaos_thread);
  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    kthread_join(unlink_threads[i]);
  }

  // Clean up
  KEXPECT_EQ(0, vfs_unlink("thread_safety_test/file1"));
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test"));
}

static void* rmdir_race_test_func1(void* arg) {
  for (int i = 0; i < THREAD_SAFETY_TEST_ITERS / 10; ++i) {
    KEXPECT_EQ(0, vfs_mkdir("thread_safety_test/dir", VFS_S_IRWXU));
    if (i % 2 == 0) scheduler_yield();
    // Could fail if other thread deletes first.
    int result = vfs_rmdir("thread_safety_test/dir");
    if (result < 0) {
      KEXPECT_EQ(-ENOENT, result);
    }
  }
  return 0;
}

static void* rmdir_race_test_func2(void* arg) {
  // TODO(aoates): use lock, atomic, or notification.
  bool* done = (bool*)arg;
  while (!*done) {
    int result = vfs_rmdir("thread_safety_test/dir");
    if (result < 0) {
      KEXPECT_EQ(-ENOENT, result);
    }
    scheduler_yield();
  }
  return 0;
}

static void rmdir_race_test(void) {
  KTEST_BEGIN("vfs_rmdir() race test");
  kthread_t creating_thread, chaos_thread;
  kthread_t rmdir_threads[THREAD_SAFETY_TEST_THREADS];

  // Set things up.
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test", 0));

  chaos_args_t chaos_args;
  chaos_args.path = "thread_safety_test";
  chaos_args.done = false;
  KEXPECT_EQ(0, proc_thread_create(&chaos_thread, &chaos_helper, &chaos_args));

  KEXPECT_EQ(
      0, proc_thread_create(&creating_thread, &rmdir_race_test_func1, NULL));

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&rmdir_threads[i], &rmdir_race_test_func2,
                                     &chaos_args.done));
  }

  kthread_join(creating_thread);
  chaos_args.done = true;
  kthread_join(chaos_thread);
  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    kthread_join(rmdir_threads[i]);
  }

  // Clean up
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test"));
}

static void get_path_test(void) {
  KTEST_BEGIN("vfs_get_vnode_path(): basic test");
  const int kBufSize = 200;
  char buf[kBufSize];

  vfs_mkdir("/vnode_path_test", 0);
  vfs_mkdir("/vnode_path_test/a", 0);
  vfs_mkdir("/vnode_path_test/a/b", 0);
  create_file("/vnode_path_test/file", RWX);
  create_file("/vnode_path_test/a/file", RWX);

#define EXPECT_PATH(expected_path, path)                      \
  do {                                                        \
    int vnode_num = vfs_get_vnode_for_path(path);             \
    vnode_t* vnode = vfs_get(vfs_get_root_fs(), vnode_num);   \
    KEXPECT_EQ(kstrlen(expected_path),                        \
               vfs_get_vnode_dir_path(vnode, buf, kBufSize)); \
    KEXPECT_STREQ((expected_path), buf);                      \
    vfs_put(vnode);                                           \
  } while (0)

#define EXPECT_PATH_ERROR(error, path)                               \
  do {                                                               \
    int vnode_num = vfs_get_vnode_for_path(path);                    \
    vnode_t* vnode = vfs_get(vfs_get_root_fs(), vnode_num);          \
    KEXPECT_EQ(error, vfs_get_vnode_dir_path(vnode, buf, kBufSize)); \
    vfs_put(vnode);                                                  \
  } while (0)

  EXPECT_PATH("/vnode_path_test", "/vnode_path_test");
  EXPECT_PATH("/vnode_path_test/a", "/vnode_path_test//a");
  EXPECT_PATH("/vnode_path_test/a", "/vnode_path_test/a/.");
  EXPECT_PATH("/vnode_path_test/a", "/vnode_path_test/a/./");
  EXPECT_PATH("/vnode_path_test", "/vnode_path_test/a/../");
  EXPECT_PATH("/vnode_path_test/a", "/vnode_path_test/a/../a");
  EXPECT_PATH("/vnode_path_test/a/b", "/vnode_path_test/a/../a/b");
  EXPECT_PATH_ERROR(-ENOTDIR, "/vnode_path_test/a/../file");
  EXPECT_PATH_ERROR(-ENOTDIR, "/vnode_path_test/a/../a/./file");

  // TODO(aoates): test across mount points.
  // TODO(aoates): test pathalogical cases (directories that loop to themselves,
  // have no parent, etc).
  // TODO(aoates): test for ENOTDIR on non-regular files

  KEXPECT_EQ(0, vfs_unlink("/vnode_path_test/a/file"));
  KEXPECT_EQ(0, vfs_unlink("/vnode_path_test/file"));
  KEXPECT_EQ(0, vfs_rmdir("/vnode_path_test/a/b"));
  KEXPECT_EQ(0, vfs_rmdir("/vnode_path_test/a"));
  KEXPECT_EQ(0, vfs_rmdir("/vnode_path_test"));
}

static void cwd_test(void) {
  const int kBufSize = 100;
  char  buf[kBufSize];

#define EXPECT_CWD(path) \
  KEXPECT_EQ(kstrlen(path), vfs_getcwd(buf, kBufSize)); \
  KEXPECT_STREQ((path), buf)

  vfs_mkdir("/cwd_test", 0);
  vfs_mkdir("/cwd_test/a", 0);
  create_file("/cwd_test/file", RWX);

  KTEST_BEGIN("vfs_getcwd(): root test");
  EXPECT_CWD("/");
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, 1));

  KTEST_BEGIN("vfs_chdir(): basic test");
  KEXPECT_EQ(0, vfs_chdir("/cwd_test/a"));
  EXPECT_CWD("/cwd_test/a");

  KTEST_BEGIN("vfs_chdir(): chdir to '/'");
  KEXPECT_EQ(0, vfs_chdir("/"));
  EXPECT_CWD("/");

  KTEST_BEGIN("vfs_chdir(): chdir to '/' via ..");
  KEXPECT_EQ(0, vfs_chdir("/cwd_test/./../."));
  EXPECT_CWD("/");

  KTEST_BEGIN("vfs_chdir(): vfs_chdir('..')");
  KEXPECT_EQ(0, vfs_chdir("/cwd_test/a"));
  KEXPECT_EQ(0, vfs_chdir(".."));
  EXPECT_CWD("/cwd_test");

  KTEST_BEGIN("vfs_chdir(): relative path");
  KEXPECT_EQ(0, vfs_chdir("a"));
  EXPECT_CWD("/cwd_test/a");

  KTEST_BEGIN("vfs_chdir(): absolute path from non-root");
  KEXPECT_EQ(0, vfs_chdir("/cwd_test"));
  EXPECT_CWD("/cwd_test");

  KTEST_BEGIN("vfs_chdir(): non-existent directory");
  KEXPECT_EQ(-ENOENT, vfs_chdir("b"));
  EXPECT_CWD("/cwd_test");

  KTEST_BEGIN("vfs_chdir(): non-existent directory in path");
  KEXPECT_EQ(-ENOENT, vfs_chdir("b/dir"));
  EXPECT_CWD("/cwd_test");

  KTEST_BEGIN("vfs_chdir(): chdir into a file");
  KEXPECT_EQ(-ENOTDIR, vfs_chdir("file"));
  EXPECT_CWD("/cwd_test");

  KTEST_BEGIN("vfs_chdir(): chdir with a file in the path");
  KEXPECT_EQ(-ENOTDIR, vfs_chdir("/cwd_test/file/dir"));
  EXPECT_CWD("/cwd_test");

  KTEST_BEGIN("vfs_chdir(): bad arguments");
  KEXPECT_EQ(-ENOENT, vfs_chdir(""));

  KTEST_BEGIN("vfs_getcwd(): bad arguments");
  KEXPECT_EQ(-EINVAL, vfs_getcwd(0x0, 5));
  KEXPECT_EQ(-EINVAL, vfs_getcwd(buf, -1));
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, 0));
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, 3));
  const int len = vfs_getcwd(buf, kBufSize);
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, len));

  KTEST_BEGIN("vfs_open(): respects cwd");
  create_file("/cwd_test/cwd_open_file", RWX);
  vfs_chdir("/cwd_test");
  int fd = vfs_open("cwd_open_file", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    vfs_close(fd);
  }

  KTEST_BEGIN("vfs_mkdir(): respects cwd");
  vfs_chdir("/cwd_test");
  vfs_mkdir("cwd_mkdir_dir", 0);
  EXPECT_CAN_CREATE_FILE("/cwd_test/cwd_mkdir_dir/file");
  KEXPECT_EQ(0, vfs_rmdir("/cwd_test/cwd_mkdir_dir"));

  KTEST_BEGIN("vfs_rmdir(): respects cwd");
  vfs_chdir("/cwd_test");
  vfs_mkdir("/cwd_test/cwd_rmdir_dir", 0);
  KEXPECT_EQ(0, vfs_rmdir("cwd_rmdir_dir"));

  KTEST_BEGIN("vfs_unlink(): respects cwd");
  vfs_chdir("/cwd_test");
  create_file("/cwd_test/cwd_unlink_file", RWX);
  KEXPECT_EQ(0, vfs_unlink("cwd_unlink_file"));

  KTEST_BEGIN("vfs_open(): '.' with cwd");
  vfs_chdir("/cwd_test");
  fd = vfs_open(".", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  KTEST_BEGIN("vfs_open(): '..' with cwd");
  vfs_chdir("/cwd_test");
  fd = vfs_open("..", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  // TODO test:
  // rmdir() the cwd
  // cwd through a symlink (and getcwd after)
  // cwd through a directory in a sub fs with the same inode number as the root
  // of the root fs
  // refcounts on the directories
  // cwd through an unlinked directory
  // simultaneous open/read/write/close calls
  // pos is maintained on error

  // Clean up.
  vfs_chdir("/");
  KEXPECT_EQ(0, vfs_unlink("/cwd_test/cwd_open_file"));
  KEXPECT_EQ(0, vfs_unlink("/cwd_test/file"));
  KEXPECT_EQ(0, vfs_rmdir("/cwd_test/a"));
  KEXPECT_EQ(-0, vfs_rmdir("/cwd_test"));
#undef EXPECT_CWD
}

static void rw_test(void) {
  const char kFile[] = "/rw_test_file";
  const char kDir[] = "/rw_test_dir";
  const int kBufSize = 512;
  char buf[kBufSize];
  create_file(kFile, RWX);
  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  KTEST_BEGIN("vfs_write(): basic write test");
  int fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(26, vfs_write(fd, "abcdefghijklmnopqrstuvwxyz", 26));
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): basic read test");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(26, vfs_read(fd, buf, kBufSize));
  buf[26] = '\0';
  KEXPECT_STREQ("abcdefghijklmnopqrstuvwxyz", buf);
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): read at end of file test");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(26, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, vfs_read(fd, buf, kBufSize));
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): chunked read test");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(10, vfs_read(fd, buf, 10));
  buf[10] = '\0';
  KEXPECT_STREQ("abcdefghij", buf);
  KEXPECT_EQ(10, vfs_read(fd, buf, 10));
  KEXPECT_STREQ("klmnopqrst", buf);
  KEXPECT_EQ(6, vfs_read(fd, buf, 10));
  buf[6] = '\0';
  KEXPECT_STREQ("uvwxyz", buf);
  vfs_close(fd);

  vfs_unlink(kFile);
  create_file(kFile, RWX);

  KTEST_BEGIN("vfs_write(): chunked write test");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(3, vfs_write(fd, "def", 3));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  buf[6] = '\0';
  KEXPECT_STREQ("abcdef", buf);
  vfs_close(fd);

  KTEST_BEGIN("vfs_write(): overwrite test");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(3, vfs_write(fd, "ABC", 3));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  buf[6] = '\0';
  KEXPECT_STREQ("ABCdef", buf);
  vfs_close(fd);

  KTEST_BEGIN("vfs read/write(): read/write share position");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(2, vfs_write(fd, "12", 2));
  KEXPECT_EQ(2, vfs_read(fd, buf, 2));
  buf[2] = '\0';
  KEXPECT_STREQ("Cd", buf);
  KEXPECT_EQ(2, vfs_write(fd, "56", 2));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  buf[6] = '\0';
  KEXPECT_STREQ("12Cd56", buf);
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): bad fd");
  KEXPECT_EQ(-EBADF, vfs_read(-1, buf, kBufSize));
  KEXPECT_EQ(-EBADF, vfs_read(5, buf, kBufSize));

  KTEST_BEGIN("vfs_write(): bad fd");
  KEXPECT_EQ(-EBADF, vfs_write(-1, buf, kBufSize));
  KEXPECT_EQ(-EBADF, vfs_write(5, buf, kBufSize));

  KTEST_BEGIN("vfs_read/write(): directory test");
  fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EISDIR, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(-EISDIR, vfs_write(fd, buf, kBufSize));
  vfs_close(fd);

  // TODO test:
  // trunc vs append
  // mode
  // multithread read/write test
  // multi-fd test

  // Clean up.
  KEXPECT_EQ(0, vfs_unlink(kFile));
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

static void write_large_test(void) {
  const char kFile[] = "/write_large_test";
  const int kBufSize = 4096;
  char* buf = (char*)kmalloc(kBufSize);
  char* buf_read = (char*)kmalloc(kBufSize);
  create_file(kFile, RWX);

  fill_with_pattern(2153215, buf, kBufSize);

  KTEST_BEGIN("vfs_write(): large write test");
  int fd = vfs_open(kFile, VFS_O_RDWR);

  int bytes_left = kBufSize;
  int write_chunks = 0;
  while (bytes_left > 0) {
    const int written =
        vfs_write(fd, buf + (kBufSize - bytes_left), bytes_left);
    KEXPECT_GT(written, 0);
    if (written <= 0) break;
    bytes_left -= written;
    write_chunks++;
  }
  KLOG("<wrote %d bytes in %d chunks>\n", kBufSize - bytes_left, write_chunks);

  // Read it back in.
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  bytes_left = kBufSize;
  int read_chunks = 0;
  while (bytes_left > 0) {
    const int read =
        vfs_read(fd, buf_read + (kBufSize - bytes_left), bytes_left);
    KEXPECT_GT(read, 0);
    if (read <= 0) break;
    bytes_left -= read;
    read_chunks++;
  }
  KLOG("<read %d bytes in %d chunks>\n", kBufSize - bytes_left, read_chunks);

  KEXPECT_EQ(0, kmemcmp(buf, buf_read, kBufSize));

  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));
  kfree(buf);
  kfree(buf_read);
}

// Multi-thread vfs_write() test.  Each thread repeatedly writes 'abc' and
// '1234' to a file descriptor, and at the end we verify that the writes didn't
// step on each other (i.e., each happened atomically).
#define WRITE_SAFETY_ITERS (10 * THREAD_SAFETY_MULTIPLIER)
#define WRITE_SAFETY_THREADS 5
static void* write_thread_test_func(void* arg) {
  const int fd = (intptr_t)arg;
  for (int i = 0; i < WRITE_SAFETY_ITERS; ++i) {
    int result = vfs_write(fd, "abc", 3);
    if (result != 3) {
      KEXPECT_EQ(3, result);
    }
    result = vfs_write(fd, "1234", 4);
    if (result != 4) {
      KEXPECT_EQ(4, result);
    }
  }
  return 0x0;
}

static void write_thread_test(void) {
  KTEST_BEGIN("vfs_write(): thread-safety test");
  kthread_t threads[WRITE_SAFETY_THREADS];

  create_file("/vfs_write_thread_safety_test", RWX);
  intptr_t fd = vfs_open("/vfs_write_thread_safety_test", VFS_O_RDWR);
  for (intptr_t i = 0; i < WRITE_SAFETY_THREADS; ++i) {
    KASSERT(proc_thread_create(&threads[i], &write_thread_test_func,
                               (void*)fd) == 0);
  }

  for (int i = 0; i < WRITE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  // Make sure all the writes were atomic.
  vfs_close(fd);
  fd = vfs_open("/vfs_write_thread_safety_test", VFS_O_RDWR);
  char buf[512];
  char buf2[10];
  int start_offset = 0;
  int letters = 0, nums = 0;
  while (1) {
    int len = vfs_read(fd, buf + start_offset, 100);
    if (len == 0) {
      break;
    }
    len += start_offset;
    int idx = 0;
    while (idx < len) {
      if (buf[idx] == '1') {
        if (len - idx < 4) break;
        kstrncpy(buf2, buf + idx, 4);
        buf2[4] = '\0';
        KEXPECT_STREQ(buf2, "1234");
        idx += 4;
        nums++;
      } else if (buf[idx] == 'a') {
        if (len - idx < 3) break;
        kstrncpy(buf2, buf + idx, 3);
        buf2[3] = '\0';
        KEXPECT_STREQ(buf2, "abc");
        idx += 3;
        letters++;
      } else {
        // TODO(aoates): add a better way to expect this.
        KEXPECT_EQ(0, 1);
        break;
      }
    }
    for (int i = 0; i < (len - idx); ++i) {
      buf[i] = buf[i + idx];
    }
    start_offset = (len - idx);
    kmemset(buf + start_offset, '\0', len - start_offset);
  }
  vfs_close(fd);

  KEXPECT_EQ(WRITE_SAFETY_THREADS * WRITE_SAFETY_ITERS, letters);
  KEXPECT_EQ(WRITE_SAFETY_THREADS * WRITE_SAFETY_ITERS, nums);

  KEXPECT_EQ(0, vfs_unlink("/vfs_write_thread_safety_test"));
}

static void rw_mode_test(void) {
  const char kFile[] = "/rw_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];

  // Create a file and put some data in it.
  int fd = vfs_open(kFile, VFS_O_CREAT | VFS_O_RDWR, 0);
  KEXPECT_EQ(6, vfs_write(fd, "abcdef", 6));
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): read-only file");
  fd = vfs_open(kFile, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): write-only file");
  fd = vfs_open(kFile, VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EBADF, vfs_read(fd, buf, kBufSize));
  vfs_close(fd);

  KTEST_BEGIN("vfs_write(): read-only file");
  fd = vfs_open(kFile, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EBADF, vfs_write(fd, "123456", 6));
  vfs_close(fd);

  KTEST_BEGIN("vfs_read(): write-only file");
  fd = vfs_open(kFile, VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(3, vfs_write(fd, "ABC", 3));
  vfs_close(fd);


  // Make sure the only write that succeeded was the write-only mode.
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  buf[6] = '\0';
  KEXPECT_STREQ("ABCdef", buf);
  vfs_close(fd);

  // TODO(aoates): keep the file open between tests with the same mode, and
  // verify that the invalid call doesn't modify the file pos.

  // Clean up.
  KEXPECT_EQ(0, vfs_unlink(kFile));
}

static void getdents_test(void) {
  edirent_t root_expected[] = {{0, "."}, {0, ".."}};
  edirent_t getdents_expected[] = {
    {-1, "."}, {0, ".."}, {-1, "a"}, {-1, "b"}, {-1, "c"},
    {-1, "f1"}, {-1, "f2"}};
  edirent_t getdents_a_expected[] = {
    {-1, "."}, {0, ".."}, {-1, "1"}, {-1, "f3"}};

  KTEST_BEGIN("vfs_getdents(): root");
  int fd = vfs_open("/", VFS_O_RDONLY);
  KEXPECT_EQ(0, compare_dirents(fd, 2, root_expected));
  vfs_close(fd);

  vfs_mkdir("/getdents", 0);
  vfs_mkdir("/getdents/a", 0);
  vfs_mkdir("/getdents/b", 0);
  vfs_mkdir("/getdents/c", 0);
  vfs_mkdir("/getdents/a/1", 0);
  create_file("/getdents/f1", RWX);
  create_file("/getdents/f2", RWX);
  create_file("/getdents/a/f3", RWX);

  KTEST_BEGIN("vfs_getdents(): files and directories");
  fd = vfs_open("/", VFS_O_RDONLY);
  KEXPECT_EQ(0, compare_dirents(fd, 3, (edirent_t[]){{0, "."}, {0, ".."}, {-1, "getdents"}}));
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): subdir #2");
  fd = vfs_open("/getdents", VFS_O_RDONLY);
  KEXPECT_EQ(0, compare_dirents(fd, 7, getdents_expected));
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): subdir #3");
  fd = vfs_open("/getdents/a", VFS_O_RDONLY);
  KEXPECT_EQ(0, compare_dirents(fd, 4, getdents_a_expected));
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): cwd");
  vfs_chdir("/getdents");
  fd = vfs_open(".", VFS_O_RDONLY);
  KEXPECT_EQ(0, compare_dirents(fd, 7, getdents_expected));
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): multiple calls");
  fd = vfs_open("/getdents", VFS_O_RDONLY);
  kdirent_t* buf = (kdirent_t*)kmalloc_aligned(1000, alignof(kdirent_t));
  kmemset(buf, 0xaa, 1000);
  size_t expected_size =
      align_up(sizeof(kdirent_t) + 2, alignof(kdirent_t)) * 4 +  // ., a, b, c
      align_up(sizeof(kdirent_t) + 3, alignof(kdirent_t)) * 3;   // .., f1, f2
  KEXPECT_EQ(expected_size, vfs_getdents(fd, buf, 1000));
  kmemset(buf, 0xaa, 1000);
  KEXPECT_EQ(0, vfs_getdents(fd, buf, 1000));
  kmemset(buf, 0xaa, 1000);
  KEXPECT_EQ(0, vfs_getdents(fd, buf, 1000));

  vfs_close(fd);
  fd = vfs_open("/getdents", VFS_O_RDONLY);

  kmemset(buf, 0xaa, 1000);
#if ARCH_IS_64_BIT
  KEXPECT_EQ(32, vfs_getdents(fd, buf, 50));
  KEXPECT_EQ(96, vfs_getdents(fd, buf, 100));
  KEXPECT_EQ(64, vfs_getdents(fd, buf, 95));
  KEXPECT_EQ(32, vfs_getdents(fd, buf, 95));
  KEXPECT_EQ(0, vfs_getdents(fd, buf, 100));
#else
  KEXPECT_EQ(48, vfs_getdents(fd, buf, 50));
  KEXPECT_EQ(64, vfs_getdents(fd, buf, 100));
  KEXPECT_EQ(0, vfs_getdents(fd, buf, 100));
#endif
  kfree(buf);
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): unaligned buffer");
  fd = vfs_open(".", VFS_O_RDONLY);
  char* unaligned_buf = kmalloc(100);
  KEXPECT_EQ(-EINVAL, vfs_getdents(fd, (kdirent_t*)(unaligned_buf + 1), 50));
  kfree(unaligned_buf);
  vfs_close(fd);

  // TODO(aoates): test:
  // buffer too small for one dirent
  // multiple calls to getdents
  // that we internally use tho offset instead of the dirent length to update
  // file pos.

  // Clean up.
  vfs_unlink("/getdents/a/f3");
  vfs_unlink("/getdents/f2");
  vfs_unlink("/getdents/f1");
  vfs_rmdir("/getdents/a/1");
  vfs_rmdir("/getdents/a");
  vfs_rmdir("/getdents/c");
  vfs_rmdir("/getdents/b");
  vfs_rmdir("/getdents");
  vfs_chdir("/");
}

static void seek_test(void) {
  const char kFile[] = "/seek_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];
  kmemset(buf, 0, kBufSize);
  create_file_with_data(kFile, "abcdefghijklmnopqrstuvwxyz");

  int fd = vfs_open(kFile, VFS_O_RDWR);
  KTEST_BEGIN("vfs_seek(): read");
  KEXPECT_EQ(3, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "defg", 4));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "hijk", 4));

  KTEST_BEGIN("vfs_seek(): write");
  KEXPECT_EQ(5, vfs_seek(fd, 5, VFS_SEEK_SET));
  KEXPECT_EQ(2, vfs_write(fd, "12", 2));
  KEXPECT_EQ(2, vfs_write(fd, "34", 2));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(26, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("abcde1234jklmnopqrstuvwxyz", buf);

  KTEST_BEGIN("vfs_seek(): SEEK_CUR");
  KEXPECT_EQ(3, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(5, vfs_seek(fd, 2, VFS_SEEK_CUR));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "1234", 4));

  KTEST_BEGIN("vfs_seek(): SEEK_END");
  KEXPECT_EQ(29, vfs_seek(fd, 3, VFS_SEEK_END));
  KEXPECT_EQ(2, vfs_write(fd, "12", 2));
  KEXPECT_EQ(2, vfs_write(fd, "34", 2));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(33, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kmemcmp("abcde1234jklmnopqrstuvwxyz\0\0\0" "1234", buf, 33));

  KTEST_BEGIN("vfs_seek(): negative seek");
  KEXPECT_EQ(3, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(1, vfs_seek(fd, -2, VFS_SEEK_CUR));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "bcde", 4));

  // TODO(aoates): negative seek from end.

  KTEST_BEGIN("vfs_seek(): negative seek");
  KEXPECT_EQ(3, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, -4, VFS_SEEK_CUR));
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, -1, VFS_SEEK_SET));

  KTEST_BEGIN("vfs_seek(): seek not shared across independent FDs");
  int fd1 = vfs_open(kFile, VFS_O_RDONLY);
  int fd2 = vfs_open(kFile, VFS_O_RDONLY);
  KEXPECT_EQ(3, vfs_seek(fd1, 3, VFS_SEEK_SET));
  KEXPECT_EQ(10, vfs_seek(fd2, 10, VFS_SEEK_SET));
  KEXPECT_EQ(3, vfs_read(fd1, buf, 3));
  KEXPECT_EQ(0, kmemcmp("de1", buf, 3));
  KEXPECT_EQ(3, vfs_read(fd2, buf, 3));
  KEXPECT_EQ(0, kmemcmp("klm", buf, 3));
  vfs_close(fd1);
  vfs_close(fd2);

  KTEST_BEGIN("vfs_seek(): invalid arguments");
  KEXPECT_EQ(-EBADF, vfs_seek(fd2, 0, VFS_SEEK_SET));
  KEXPECT_EQ(-EBADF, vfs_seek(10000, 0, VFS_SEEK_SET));
  KEXPECT_EQ(-EBADF, vfs_seek(-3, 0, VFS_SEEK_SET));
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, 0, 5));
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, 0, -5));

  // TODO(aoates): test,
  // seek past end with all three whences
  // seek is shared across dup()s

  // Clean up.
  vfs_close(fd);
  vfs_unlink(kFile);
}

#define BAD_INODE_SAFETY_ITERS (10 * THREAD_SAFETY_MULTIPLIER)
#define BAD_INODE_SAFETY_THREADS 5
static void* bad_inode_thread_test_func(void* arg) {
  for (int i = 0; i < BAD_INODE_SAFETY_ITERS; ++i) {
    vnode_t* node = vfs_get(vfs_get_root_fs(), 52187 + (i % 3));
    KEXPECT_EQ(0x0, (intptr_t)node);
  }
  return 0x0;
}

static void bad_inode_thread_test(void) {
  KTEST_BEGIN("vfs_get(): bad inode thread-safety test");
  kthread_t threads[BAD_INODE_SAFETY_THREADS];

  for (int i = 0; i < BAD_INODE_SAFETY_THREADS; ++i) {
    KASSERT(proc_thread_create(&threads[i], &bad_inode_thread_test_func, 0x0) ==
            0);
  }

  for (int i = 0; i < BAD_INODE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  vfs_log_cache();
}

static void get_bad_inode_test(void) {
  KTEST_BEGIN("vfs_get(): bad inode");
  vnode_t* node = vfs_get(vfs_get_root_fs(), 52187);
  KEXPECT_EQ(0x0, (intptr_t)node);

  bad_inode_thread_test();

  // TODO(aoates): test vfs_open, cwd, etc handle dangling inodes
}

void reverse_path_test(void) {
  char buf[512];
  KTEST_BEGIN("reverse_path() test");

#define TEST(in, out) \
  kstrcpy(buf, in); \
  reverse_path(buf); \
  KEXPECT_STREQ(out, buf);

  TEST("a", "a");
  TEST("/a", "a/");
  TEST("a/", "/a");

  TEST("ab", "ab");
  TEST("/ab", "ab/");
  TEST("ab/", "/ab");

  TEST("abc", "abc");
  TEST("/a/b/c", "c/b/a/");
  TEST("/a/b/c/", "/c/b/a/");
  TEST("a/b/c/", "/c/b/a");

  TEST("abc/def/", "/def/abc");

  TEST("///abc/def", "def/abc///");
  TEST("///abc/def//", "//def/abc///");
  TEST("///abc////def//", "//def////abc///");

#undef TEST
}

// Multi-thread vfs_open(VFS_O_CREAT) test.  Each thread creates a series of
// files in a particular directory.
#define CREATE_SAFETY_ITERS (10 * THREAD_SAFETY_MULTIPLIER)
#define CREATE_SAFETY_THREADS 5
static void* create_thread_test_func(void* arg) {
  const char kTestDir[] = "/create_thread_test";
  const int thread_num = (intptr_t)arg;
  for (int i = 0; i < CREATE_SAFETY_ITERS; ++i) {
    char buf[512];
    ksprintf(buf, "%s/%d.%d", kTestDir, thread_num, i);
    int fd = vfs_open(buf, VFS_O_CREAT | VFS_O_RDWR, 0);
    if (fd < 0) {
      KEXPECT_GE(fd, -0);
    } else {
      vfs_close(fd);
    }
  }
  return 0x0;
}

static void* unlink_thread_test_func(void* arg) {
  const char kTestDir[] = "/create_thread_test";
  const int thread_num = (intptr_t)arg;
  for (int i = 0; i < CREATE_SAFETY_ITERS; ++i) {
    char buf[512];
    ksprintf(buf, "%s/%d.%d", kTestDir, thread_num, i);
    int result = vfs_unlink(buf);
    if (result < 0) {
      KEXPECT_EQ(-0, result);
    }
  }
  return 0x0;
}

static void create_thread_test(void) {
  KTEST_BEGIN("vfs_open(VFS_O_CREAT): thread-safety test");
  const char kTestDir[] = "/create_thread_test";
  kthread_t threads[CREATE_SAFETY_THREADS];

  KEXPECT_EQ(0, vfs_mkdir(kTestDir, 0));
  for (intptr_t i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    KASSERT(proc_thread_create(&threads[i], &create_thread_test_func,
                               (void*)i) == 0);
  }

  for (int i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  // Make sure they're all created correctly.
  const int kNumExpected = CREATE_SAFETY_ITERS * CREATE_SAFETY_THREADS + 2;
  char** expected_names = (char**)kmalloc(sizeof(char*) * kNumExpected);
  for (int i = 0; i < kNumExpected; ++i) {
    expected_names[i] = (char*)kmalloc(30);
  }
  edirent_t* expected_dirents =
      (edirent_t*)kmalloc(sizeof(edirent_t) * kNumExpected);
  expected_dirents[0].vnode = expected_dirents[1].vnode = -1;
  expected_dirents[0].name = ".";
  expected_dirents[1].name = "..";
  for (int i = 2; i < kNumExpected; ++i) {
    ksprintf(expected_names[i], "%d.%d", (i - 2) / CREATE_SAFETY_ITERS,
             (i - 2) % CREATE_SAFETY_ITERS);
    expected_dirents[i].vnode = -1;
    expected_dirents[i].name = expected_names[i];
  }
  int fd = vfs_open(kTestDir, VFS_O_RDONLY);
  if (fd >= 0) {
    KEXPECT_EQ(0, compare_dirents(fd, kNumExpected, expected_dirents));
    vfs_close(fd);
  }

  KTEST_BEGIN("vfs_unlink(): thread-safety test");
  for (intptr_t i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    KASSERT(proc_thread_create(&threads[i], &unlink_thread_test_func,
                               (void*)i) == 0);
  }

  for (int i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  fd = vfs_open(kTestDir, VFS_O_RDONLY);
  if (fd >= 0) {
    KEXPECT_EQ(0, compare_dirents(fd, 2, expected_dirents));
    vfs_close(fd);
  }

  KEXPECT_EQ(0, vfs_rmdir(kTestDir));
  kfree(expected_dirents);
  for (int i = 0; i < kNumExpected; ++i) {
    kfree(expected_names[i]);
  }
  kfree(expected_names);
}

// Test that if we create a file, then unlink it before closing it, we can still
// read from it.
static void unlink_open_file_test(void) {
  KTEST_BEGIN("unlink() open file test");
  const char kFile[] = "unlink_open_file_test";
  const char kFile2[] = "unlink_open_file_test2";
  create_file_with_data(kFile, "123456789");

  const int fd = vfs_open(kFile, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_unlink(kFile));

  // The file should not be in the directory any more.
  EXPECT_FILE_DOESNT_EXIST(kFile);

  create_file_with_data(kFile2, "abcdefg");  // Make sure we don't reuse the inode.

  char buf[512];
  KEXPECT_EQ(9, vfs_read(fd, buf, 512));
  buf[9] = '\0';
  KEXPECT_STREQ("123456789", buf);

  KEXPECT_EQ(0, vfs_close(fd));
  EXPECT_FILE_DOESNT_EXIST(kFile);

  KEXPECT_EQ(0, vfs_unlink(kFile2));
}

// Test unlinking a directory that's open for reading.
static void unlink_open_directory_test(void) {
  KTEST_BEGIN("rmdir() open directory test");
  const char kDir[] = "unlink_open_directory_test";
  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  const int fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_rmdir(kDir));

  // The file should not be in the directory any more.
  EXPECT_FILE_DOESNT_EXIST(kDir);

  KEXPECT_EQ(0, compare_dirents(fd, 0, 0x0));

  KEXPECT_EQ(0, vfs_close(fd));
  EXPECT_FILE_DOESNT_EXIST(kDir);
}

// Test trying to create a file in an unlinked directory (that's still open for
// reading).
static void create_in_unlinked_directory(void) {
  KTEST_BEGIN("create in rmdir()'d directory test");
  const char kDir[] = "create_in_unlinked_directory_test";
  const char kFile[] = "create_in_unlinked_directory_test/file";
  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  const int fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_rmdir(kDir));

  // Try to create a file in the directory.  It should fail.
  const int fd2 = vfs_open(kFile, VFS_O_RDWR | VFS_O_CREAT, 0);
  KEXPECT_EQ(-ENOENT, fd2);

  KEXPECT_EQ(0, compare_dirents(fd, 0, 0x0));

  KEXPECT_EQ(0, vfs_close(fd));
}

// Create a file, write a pattern of N bytes to it, then verify that we can see
// it via read_page.
static void read_page_test(const char* filename, const int size) {
  const phys_addr_t page_buf_phys = page_frame_alloc();
  void* const page_buf = (void*)phys2virt(page_buf_phys);

  int fd = vfs_open(filename, VFS_O_RDWR | VFS_O_CREAT, 0);
  KEXPECT_GE(fd, 0);

  // Create a unique pattern.
  uint8_t* buf = (uint8_t*)kmalloc(size);
  fill_with_pattern(page_buf_phys, buf, size);

  // Write a few pages to the file first.
  const int kPrefixPages = 3;
  for (int i = 0; i < kPrefixPages; ++i) {
    KEXPECT_EQ(PAGE_SIZE, vfs_write(fd, page_buf, PAGE_SIZE));
  }

  // Write the pattern to the file.
  KEXPECT_EQ(size, vfs_write(fd, buf, size));

  // Get a memobj.
  memobj_t* memobj = 0x0;
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDONLY, &memobj));
  int orig_refcount = memobj->refcount;  // Not really supposed to read this...
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDONLY, &memobj));
  KEXPECT_EQ(orig_refcount + 1, memobj->refcount);
  memobj->ops->unref(memobj);

  // Read the page and make sure it matches.
  kmemset(page_buf, 0, PAGE_SIZE);
  memobj->ops->read_page(memobj, kPrefixPages, page_buf);
  KEXPECT_EQ(0, kmemcmp(page_buf, buf, size));
  for (int i = size; i < PAGE_SIZE; ++i) {
    uint8_t bufval = ((uint8_t*)page_buf)[i];
    if (bufval != 0) KEXPECT_EQ(0, bufval);
  }

  KEXPECT_EQ(0, vfs_close(fd));
  memobj->ops->unref(memobj);
  KEXPECT_EQ(0, vfs_unlink(filename));
  page_frame_free(page_buf_phys);
  kfree(buf);
}

// Test a vnode-backed memobj.
static void memobj_test(void) {
  KTEST_BEGIN("vfs_get_memobj() test");
  const char kDir[] = "memobj_test";
  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  memobj_t* unused_memobj = 0x0;

  KTEST_BEGIN("vfs_get_memobj() bad fd test");
  KEXPECT_EQ(-EBADF, vfs_get_memobj(-5, VFS_O_RDONLY, &unused_memobj));
  KEXPECT_EQ(-EBADF, vfs_get_memobj(10, VFS_O_RDONLY, &unused_memobj));
  KEXPECT_EQ(-EBADF, vfs_get_memobj(55555555, VFS_O_RDONLY, &unused_memobj));

  KTEST_BEGIN("vfs_get_memobj() directory test");
  int dir_fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_EQ(-EISDIR, vfs_get_memobj(dir_fd, VFS_O_RDONLY, &unused_memobj));
  vfs_close(dir_fd);

  KTEST_BEGIN("vfs_get_memobj() mode test");
  const char kFile[] = "memobj_test/file";
  int fd = vfs_open(kFile, VFS_O_RDONLY | VFS_O_CREAT, 0);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDONLY, &unused_memobj));
  unused_memobj->ops->unref(unused_memobj);
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_WRONLY, &unused_memobj));
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_RDWR, &unused_memobj));
  KEXPECT_EQ(0, vfs_close(fd));

  fd = vfs_open(kFile, VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_RDONLY, &unused_memobj));
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_WRONLY, &unused_memobj));
  unused_memobj->ops->unref(unused_memobj);
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_RDWR, &unused_memobj));
  KEXPECT_EQ(0, vfs_close(fd));

  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDONLY, &unused_memobj));
  unused_memobj->ops->unref(unused_memobj);
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_WRONLY, &unused_memobj));
  unused_memobj->ops->unref(unused_memobj);
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDWR, &unused_memobj));
  unused_memobj->ops->unref(unused_memobj);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_get_memobj(): read_page() full page");
  read_page_test("full_page", PAGE_SIZE);

  KTEST_BEGIN("vfs_get_memobj(): read_page() half page");
  read_page_test("half_page", PAGE_SIZE / 2);

  KTEST_BEGIN("vfs_get_memobj(): read_page() eighth page");
  read_page_test("eighth_page", PAGE_SIZE / 8);

  KTEST_BEGIN("vfs_get_memobj(): read_page() non-divisible page");
  read_page_test("non_divisible_page", PAGE_SIZE - 71);

  KEXPECT_EQ(0, vfs_unlink(kFile));
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

// TODO(aoates): test for memobj write_page as well.

static void mknod_test(void) {
  const char kDir[] = "mknod_test_dir";
  const char kRegFile[] = "mknod_test_dir/reg";
  const char kCharDevFile[] = "mknod_test_dir/char";
  const char kBlockDevFile[] = "mknod_test_dir/block";

  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  KTEST_BEGIN("mknod(): invalid file type test");
  KEXPECT_EQ(-EINVAL, vfs_mknod(kRegFile, VFS_S_IFMT, kmakedev(0, 0)));
  KEXPECT_EQ(-EINVAL, vfs_mknod(kRegFile, 0xffff, kmakedev(0, 0)));
  EXPECT_VNODE_REFCOUNT(0, kDir);

  KTEST_BEGIN("mknod(): regular file test");
  KEXPECT_EQ(0, vfs_mknod(kRegFile, VFS_S_IFREG, kmakedev(0, 0)));
  EXPECT_VNODE_REFCOUNT(0, kRegFile);
  EXPECT_VNODE_REFCOUNT(0, kDir);

  int fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(5, vfs_write(fd, "abcde", 5));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  char buf[10];
  KEXPECT_EQ(5, vfs_read(fd, buf, 10));
  KEXPECT_EQ(0, kmemcmp("abcde", buf, 5));
  vfs_close(fd);

  KTEST_BEGIN("mknod(): empty path test");
  KEXPECT_EQ(-ENOENT, vfs_mknod("", VFS_S_IFREG, kmakedev(0, 0)));

  KTEST_BEGIN("mknod(): existing file test");
  KEXPECT_EQ(-EEXIST, vfs_mknod(kRegFile, VFS_S_IFREG, kmakedev(0, 0)));

  KTEST_BEGIN("mknod(): bath path test");
  KEXPECT_EQ(-ENOENT, vfs_mknod("bad/path/test", VFS_S_IFREG, kmakedev(0, 0)));

  EXPECT_VNODE_REFCOUNT(0, kDir);

  KTEST_BEGIN("mknod(): character device file test");
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR, kmakedev(0, 0)));
  EXPECT_VNODE_REFCOUNT(0, kCharDevFile);
  EXPECT_VNODE_REFCOUNT(0, kDir);

  fd = vfs_open(kCharDevFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  KTEST_BEGIN("mknod(): block device file test");
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, kmakedev(0, 0)));
  EXPECT_VNODE_REFCOUNT(0, kBlockDevFile);
  EXPECT_VNODE_REFCOUNT(0, kDir);

  fd = vfs_open(kBlockDevFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  KTEST_BEGIN("mknod(): socket file type test");
  KEXPECT_EQ(-EINVAL, vfs_mknod(kRegFile, VFS_S_IFSOCK, kmakedev(0, 0)));
  EXPECT_VNODE_REFCOUNT(0, kDir);

  // TODO(aoates): test character device functionality.

  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  vfs_rmdir(kDir);
}

static void mksocket_test(void) {
  const char kDir[] = "mksocket_test_dir";
  const char kFile[] = "mksocket_test_dir/sock";

  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  KTEST_BEGIN("vfs_mksocket(): invalid file type test");
  vnode_t* vnode = NULL;
  KEXPECT_EQ(-EINVAL, vfs_mksocket(kFile, VFS_S_IFMT, &vnode));
  KEXPECT_EQ(-EINVAL, vfs_mksocket(kFile, 0xffff, &vnode));
  KEXPECT_EQ(-EINVAL, vfs_mksocket(kFile, VFS_S_IFREG, &vnode));
  KEXPECT_EQ(-EINVAL, vfs_mksocket(kFile, VFS_S_IFIFO, &vnode));
  EXPECT_VNODE_REFCOUNT(0, kDir);

  KTEST_BEGIN("vfs_mksocket(): basic test");
  KEXPECT_EQ(0, vfs_mksocket(kFile, VFS_S_IFSOCK, &vnode));
  KEXPECT_NE(NULL, vnode);
  KEXPECT_EQ(VNODE_SOCKET, vnode->type);

  KTEST_BEGIN("vfs_stat(): on socket file");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(stat.st_ino, vnode->num);
  KEXPECT_EQ(1, stat.st_nlink);

  KTEST_BEGIN("vfs_lstat(): on socket file");
  kmemset(&stat, 0, sizeof(stat));
  KEXPECT_EQ(0, vfs_lstat(kFile, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(stat.st_ino, vnode->num);
  KEXPECT_EQ(1, stat.st_nlink);
  VFS_PUT_AND_CLEAR(vnode);

  KTEST_BEGIN("vfs_fstat(): on socket file");
  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  kmemset(&stat, 0, sizeof(stat));
  KEXPECT_EQ(0, vfs_fstat(sock, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(0, stat.st_nlink);
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("vfs_open(): fails on socket file");
  KEXPECT_EQ(-EOPNOTSUPP, vfs_open(kFile, VFS_O_RDONLY));
  KEXPECT_EQ(-EOPNOTSUPP, vfs_open(kFile, VFS_O_WRONLY));
  KEXPECT_EQ(-EOPNOTSUPP, vfs_open(kFile, VFS_O_RDWR));

  KTEST_BEGIN("vfs_rmdir(): fails on socket file");
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir(kFile));

  KTEST_BEGIN("vfs_mkdir(): fails over socket file");
  KEXPECT_EQ(-EEXIST, vfs_mkdir(kFile, VFS_S_IRUSR));

  KTEST_BEGIN("vfs_mknod(): fails over socket file");
  KEXPECT_EQ(-EEXIST, vfs_mknod(kFile, VFS_S_IFIFO, 0));

  KTEST_BEGIN("vfs_rmdir(): fails on socket file");
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir(kFile));

  KTEST_BEGIN("vfs_chdir(): fails on socket file");
  KEXPECT_EQ(-ENOTDIR, vfs_chdir(kFile));

  KTEST_BEGIN("vfs_readlink(): fails on socket file");
  char buf[100];
  KEXPECT_EQ(-EINVAL, vfs_readlink(kFile, buf, 100));

  KTEST_BEGIN("vfs_truncate(): fails on socket file");
  KEXPECT_EQ(-EINVAL, vfs_truncate(kFile, 0));
  KEXPECT_EQ(-EINVAL, vfs_truncate(kFile, 100));

  // TODO(aoates): test other path-taking syscalls: vfs_link, vfs_rename,
  // vfs_chown, vfs_lchown, vfs_chmod, vfs_symlink.

  KEXPECT_EQ(0, vfs_unlink(kFile));
  vfs_rmdir(kDir);
}

static void block_device_test(void) {
  const char kDir[] = "block_dev_test_dir";
  const char kBlockDevFile[] = "block_dev_test_dir/block";
  const int kRamdiskSize = PAGE_SIZE * 3;

  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  // Create a ramdisk for the test.
  ramdisk_t* ramdisk = 0x0;
  block_dev_t ramdisk_bd;
  KASSERT(ramdisk_create(kRamdiskSize, &ramdisk) == 0);
  ramdisk_set_blocking(ramdisk, 1, 1);
  ramdisk_dev(ramdisk, &ramdisk_bd);

  apos_dev_t dev = kmakedev(DEVICE_MAJOR_RAMDISK, DEVICE_ID_UNKNOWN);
  KEXPECT_EQ(0, dev_register_block(&ramdisk_bd, &dev));

  KTEST_BEGIN("vfs: block device file test");
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, dev));

  int fd = vfs_open(kBlockDevFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  // Write to the ramdisk, then read from the fd.
  const int kBufSize = 512;
  KASSERT(kBufSize == ramdisk_bd.sector_size);
  char buf[kBufSize];
  kmemset(buf, 0, kBufSize);

  // Zero out the entire ramdisk.
  for (int i = 0; i < kRamdiskSize / kBufSize; ++i) {
    KEXPECT_EQ(kBufSize, ramdisk_bd.write(&ramdisk_bd, i, buf, kBufSize, 0));
  }

  KTEST_BEGIN("vfs_read(): block device");
  kstrcpy(buf, "ramdisk");
  KEXPECT_EQ(kBufSize, ramdisk_bd.write(&ramdisk_bd, 0, buf, kBufSize, 0));
  kmemset(buf, 0, kBufSize);
  KEXPECT_EQ(10, vfs_read(fd, buf, 10));
  KEXPECT_EQ(0, kmemcmp("ramdisk\0\0\0", buf, 10));

  KTEST_BEGIN("vfs_write(): block device");
  KEXPECT_EQ(7, vfs_write(fd, "written", 7));
  KEXPECT_EQ(kBufSize, ramdisk_bd.read(&ramdisk_bd, 0, buf, kBufSize, 0));
  KEXPECT_EQ(0, kmemcmp("ramdisk\0\0\0written\0\0\0", buf, 20));

  KTEST_BEGIN("vfs_seek(): block device: seek within block");
  KEXPECT_EQ(kBufSize * 2 + 5, vfs_seek(fd, kBufSize * 2 + 5, VFS_SEEK_SET));
  KEXPECT_EQ(6, vfs_write(fd, "write2", 6));
  KEXPECT_EQ(kBufSize, ramdisk_bd.read(&ramdisk_bd, 2, buf, kBufSize, 0));
  KEXPECT_EQ(0, kmemcmp("\0\0\0\0\0write2\0\0\0\0", buf, 15));

  KTEST_BEGIN("vfs_seek(): block device: seek past end of device");
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, kBufSize * 30, VFS_SEEK_SET));

  KTEST_BEGIN("vfs_truncate(): block device");
  KEXPECT_EQ(-EINVAL, vfs_truncate(kBlockDevFile, 0));
  KEXPECT_EQ(-EINVAL, vfs_truncate(kBlockDevFile, 5));

  KTEST_BEGIN("vfs_ftruncate(): block device");
  KEXPECT_EQ(-EINVAL, vfs_ftruncate(fd, 0));
  KEXPECT_EQ(-EINVAL, vfs_ftruncate(fd, 5));

  KTEST_BEGIN("vfs_open(): O_TRUNC on block device");
  KEXPECT_EQ(-EINVAL, vfs_open(kBlockDevFile, VFS_O_RDWR | VFS_O_TRUNC));

  vfs_close(fd);

  // Cleanup.
  // TODO(aoates): make this work
  block_cache_clear_unpinned();  // Make sure all entries for dev are flushed.
  KASSERT(dev_unregister_block(dev) == 0);
  ramdisk_destroy(ramdisk);

  vfs_unlink(kBlockDevFile);
  vfs_rmdir(kDir);
}

static void fs_dev_test(void) {
  KTEST_BEGIN("VFS fs_t::dev test");

  vnode_t* vnode = vfs_get_root_vnode();
  if (kstrcmp(vnode->fs->fstype, "ramfs") == 0) {
    KEXPECT_EQ(DEVICE_ID_UNKNOWN, kmajor(vnode->fs->dev));
    KEXPECT_EQ(DEVICE_ID_UNKNOWN, kminor(vnode->fs->dev));
  } else {
    KEXPECT_NE(DEVICE_ID_UNKNOWN, kmajor(vnode->fs->dev));
    KEXPECT_NE(DEVICE_ID_UNKNOWN, kminor(vnode->fs->dev));
  }

  vfs_put(vnode);
}

static void KEXPECT_STAT_EQ(const apos_stat_t* A, const apos_stat_t* B) {
  int result = kmemcmp(A, B, sizeof(apos_stat_t));
  KEXPECT_EQ(0, result);

  if (result != 0) {
    KEXPECT_EQ(kmajor(A->st_dev), kmajor(B->st_dev));
    KEXPECT_EQ(kminor(A->st_dev), kminor(B->st_dev));
    KEXPECT_EQ(A->st_ino, B->st_ino);
    KEXPECT_EQ(A->st_mode, B->st_mode);
    KEXPECT_EQ(A->st_nlink, B->st_nlink);
    KEXPECT_EQ(kmajor(A->st_rdev), kmajor(B->st_rdev));
    KEXPECT_EQ(kminor(A->st_rdev), kminor(B->st_rdev));
    KEXPECT_EQ(A->st_size, B->st_size);
    KEXPECT_EQ(A->st_blksize, B->st_blksize);
    KEXPECT_EQ(A->st_blocks, B->st_blocks);
  }
}

static void lstat_test(void) {
  const char kDir[] = "stat_test_dir";
  const char kRegFile[] = "stat_test_dir/reg";
  const char kCharDevFile[] = "stat_test_dir/char";
  const char kBlockDevFile[] = "stat_test_dir/block";

  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  // TODO(aoates): test the following
  //  * st_dev
  //  * linked file
  //  * fstat
  apos_stat_t stat, fstat;

  KTEST_BEGIN("lstat(): regular file test (empty)");
  create_file(kRegFile, RWX);

  kmemset(&stat, 0xFF, sizeof(stat));
  kmemset(&fstat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_lstat(kRegFile, &stat));
  // TODO(aoates): test st_dev, blksize.
  KEXPECT_EQ(vfs_get_vnode_for_path(kRegFile), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
             stat.st_mode);
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_EQ(0, stat.st_blocks);

  KTEST_BEGIN("fstat(): regular file test (empty)");
  int fd = vfs_open(kRegFile, VFS_O_RDONLY);
  KEXPECT_EQ(0, vfs_fstat(fd, &fstat));
  KEXPECT_STAT_EQ(&stat, &fstat);
  vfs_close(fd);

  vfs_unlink(kRegFile);

  KTEST_BEGIN("lstat(): regular file test (with data)");
  create_file_with_data(kRegFile, "abcde");

  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_lstat(kRegFile, &stat));
  // TODO(aoates): test st_dev, blksize.
  KEXPECT_EQ(vfs_get_vnode_for_path(kRegFile), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFREG, stat.st_mode);
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_EQ(5, stat.st_size);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_GE(stat.st_blocks, 1);

  KTEST_BEGIN("fstat(): regular file test (with data)");
  fd = vfs_open(kRegFile, VFS_O_RDONLY);
  KEXPECT_EQ(0, vfs_fstat(fd, &fstat));
  KEXPECT_STAT_EQ(&stat, &fstat);
  vfs_close(fd);

  // TODO(aoates): test hard-linked file once they're supported.

  KTEST_BEGIN("lstat(): directory test");
  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_lstat(kDir, &stat));
  // TODO(aoates): test st_dev, blksize.
  KEXPECT_EQ(vfs_get_vnode_for_path(kDir), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFDIR, stat.st_mode);
  KEXPECT_EQ(2, stat.st_nlink);
  KEXPECT_GE(stat.st_size, 0);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_GE(stat.st_blocks, 1);

  KTEST_BEGIN("fstat(): directory test");
  fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_EQ(0, vfs_fstat(fd, &fstat));
  KEXPECT_STAT_EQ(&stat, &fstat);
  vfs_close(fd);

  KTEST_BEGIN("lstat(): character device file test");
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR, kmakedev(1, 2)));

  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_lstat(kCharDevFile, &stat));
  // TODO(aoates): test st_dev, blksize.
  KEXPECT_EQ(vfs_get_vnode_for_path(kCharDevFile), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFCHR, stat.st_mode);
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_EQ(1, kmajor(stat.st_rdev));
  KEXPECT_EQ(2, kminor(stat.st_rdev));
  KEXPECT_GE(stat.st_size, 0);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_EQ(0, stat.st_blocks);

  KTEST_BEGIN("fstat(): character device file test");
  fd = vfs_open(kCharDevFile, VFS_O_RDONLY);
  KEXPECT_EQ(0, vfs_fstat(fd, &fstat));
  KEXPECT_STAT_EQ(&stat, &fstat);
  vfs_close(fd);

  KTEST_BEGIN("lstat(): blockdevice file test");
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, kmakedev(3, 4)));

  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_lstat(kBlockDevFile, &stat));
  // TODO(aoates): test st_dev, blksize.
  KEXPECT_EQ(vfs_get_vnode_for_path(kBlockDevFile), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFBLK, stat.st_mode);
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_EQ(3, kmajor(stat.st_rdev));
  KEXPECT_EQ(4, kminor(stat.st_rdev));
  KEXPECT_GE(stat.st_size, 0);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_EQ(0, stat.st_blocks);

  KTEST_BEGIN("fstat(): blockdevice file test");
  fd = vfs_open(kBlockDevFile, VFS_O_RDONLY);
  KEXPECT_EQ(0, vfs_fstat(fd, &fstat));
  KEXPECT_STAT_EQ(&stat, &fstat);
  vfs_close(fd);

  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  vfs_rmdir(kDir);

  // TODO(aoates): test fstat on fds with different modes.
}

static void stat_test(void) {
  const char kDir[] = "stat_test_dir";
  const char kRegFile[] = "stat_test_dir/reg";
  const char kFileLink[] = "stat_test_dir/reg_link";
  const char kDirLink[] = "stat_test_dir/dir_link";
  const char kBadLink[] = "stat_test_dir/bad_link";

  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  apos_stat_t stat;

  KTEST_BEGIN("stat(): regular file test (empty)");
  create_file(kRegFile, RWX);

  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_stat(kRegFile, &stat));
  KEXPECT_EQ(vfs_get_vnode_for_path(kRegFile), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
             stat.st_mode);
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_EQ(0, stat.st_blocks);


  KTEST_BEGIN("stat(): link to regular file test");
  KEXPECT_EQ(0, vfs_symlink("reg", kFileLink));

  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_stat(kFileLink, &stat));
  KEXPECT_EQ(vfs_get_vnode_for_path(kRegFile), stat.st_ino);
  KEXPECT_NE(vfs_get_vnode_for_path(kFileLink), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
             stat.st_mode);
  KEXPECT_EQ(1, stat.st_nlink);
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_GT(stat.st_blksize, 0);
  KEXPECT_EQ(0, stat.st_blocks);


  KTEST_BEGIN("stat(): link to directory");
  KEXPECT_EQ(0, vfs_symlink(".", kDirLink));

  kmemset(&stat, 0xFF, sizeof(stat));
  KEXPECT_EQ(0, vfs_stat(kDirLink, &stat));
  KEXPECT_EQ(VFS_S_IFDIR, stat.st_mode);

  KTEST_BEGIN("stat(): dangling link");
  KEXPECT_EQ(0, vfs_symlink("bad", kBadLink));
  KEXPECT_EQ(-ENOENT, vfs_stat(kBadLink, &stat));
  KEXPECT_EQ(-ENOENT, vfs_stat("badtarget", &stat));


  KTEST_BEGIN("stat(): bad args");
  KEXPECT_EQ(-EINVAL, vfs_stat(0x0, &stat));
  KEXPECT_EQ(-EINVAL, vfs_stat(kDirLink, 0x0));

  vfs_unlink(kBadLink);
  vfs_unlink(kFileLink);
  vfs_unlink(kDirLink);
  vfs_unlink(kRegFile);
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

static void initial_owner_test_func(void* arg) {
  const kuid_t kTestUserA = 1;
  const kuid_t kTestUserB = 2;
  const kgid_t kTestGroupA = 3;
  const kgid_t kTestGroupB = 4;

  const char kDir[] = "owner_test_dir";
  const char kSubDir[] = "owner_test_dir/dir";
  const char kRegFile[] = "owner_test_dir/reg";
  const char kCharDevFile[] = "owner_test_dir/char";
  const char kBlockDevFile[] = "owner_test_dir/block";

  KTEST_BEGIN("vfs_open() sets uid/gid: regular file test");
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));
  KEXPECT_EQ(0, setregid(kTestGroupA, kTestGroupB));
  KEXPECT_EQ(0, setreuid(kTestUserA, kTestUserB));

  create_file(kRegFile, RWX);
  EXPECT_OWNER_IS(kRegFile, kTestUserB, kTestGroupB);

  KTEST_BEGIN("vfs_mkdir() sets uid/gid: directory test");
  KEXPECT_EQ(0, vfs_mkdir(kSubDir, 0));
  EXPECT_OWNER_IS(kSubDir, kTestUserB, kTestGroupB);

  KTEST_BEGIN("vfs_mknod() sets uid/gid: character device file test");
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR, kmakedev(1, 2)));
  EXPECT_OWNER_IS(kCharDevFile, kTestUserB, kTestGroupB);

  KTEST_BEGIN("vfs_mknod() sets uid/gid: block device file test");
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, kmakedev(3, 4)));
  EXPECT_OWNER_IS(kBlockDevFile, kTestUserB, kTestGroupB);

  // TODO(aoates): test time metadata (and mode?) as well.
  KTEST_BEGIN("vfs_symlink() sets uid/gid");
  KEXPECT_EQ(0, vfs_symlink("not_a_path", "owner_test_dir/link1"));
  EXPECT_OWNER_IS("owner_test_dir/link1", kTestUserB, kTestGroupB);
  KEXPECT_EQ(0, vfs_symlink(kRegFile, "owner_test_dir/link2"));
  EXPECT_OWNER_IS("owner_test_dir/link2", kTestUserB, kTestGroupB);
  KEXPECT_EQ(0, vfs_symlink(kSubDir, "owner_test_dir/link3"));
  EXPECT_OWNER_IS("owner_test_dir/link3", kTestUserB, kTestGroupB);

  vfs_unlink("owner_test_dir/link1");
  vfs_unlink("owner_test_dir/link2");
  vfs_unlink("owner_test_dir/link3");
  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  vfs_rmdir(kSubDir);
}

static void initial_owner_test(void) {
  kpid_t child_pid = proc_fork(&initial_owner_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_wait(0x0);
  KEXPECT_EQ(0, vfs_rmdir("owner_test_dir"));
}

// Helper that opens the given file, runs vfs_fchown() on the file descriptor,
// then closes it and returns the result.
static int do_fchown(const char* path, kuid_t owner, kgid_t group) {
  int fd = vfs_open(path, VFS_O_RDWR);
  if (fd < 0) return fd;
  int result = vfs_fchown(fd, owner, group);
  vfs_close(fd);
  return result;
}

static void non_root_chown_test_func(void* arg) {
  // TODO(aoates): consolidate these constants?
  const kuid_t kTestUserA = 1;
  const kuid_t kTestUserB = 2;
  const kuid_t kTestUserC = 3;
  const kgid_t kTestGroupA = 4;
  const kgid_t kTestGroupB = 5;
  const kgid_t kTestGroupC = 6;

  const char kRootFile[] = "chown_test_dir/rootfile";
  const char kUAGA[] = "chown_test_dir/userAgrpA";
  const char kUAGB[] = "chown_test_dir/userAgrpB";
  const char kUBGA[] = "chown_test_dir/userBgrpA";
  const char kUBGB[] = "chown_test_dir/userBgrpB";
  const char kUCGA[] = "chown_test_dir/userCgrpA";
  const char kUCGB[] = "chown_test_dir/userCgrpB";

  KTEST_BEGIN("vfs_lchown()/vfs_fchown(): setup for user tests");
  create_file(kRootFile, RWX);
  create_file(kUAGA, RWX);
  create_file(kUAGB, RWX);
  create_file(kUBGA, RWX);
  create_file(kUBGB, RWX);
  create_file(kUCGA, RWX);
  create_file(kUCGB, RWX);

  KEXPECT_EQ(0, vfs_lchown(kUAGA, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kUAGB, kTestUserA, kTestGroupB));
  KEXPECT_EQ(0, vfs_lchown(kUBGA, kTestUserB, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kUBGB, kTestUserB, kTestGroupB));
  KEXPECT_EQ(0, vfs_lchown(kUCGA, kTestUserC, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kUCGB, kTestUserC, kTestGroupB));

  KEXPECT_EQ(0, setregid(kTestGroupA, kTestGroupB));
  KEXPECT_EQ(0, setreuid(kTestUserA, kTestUserB));

  KTEST_BEGIN("chown(): cannot change uid if non-root");
  KEXPECT_EQ(-EPERM, vfs_lchown(kRootFile, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUAGA, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUAGB, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUBGA, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUBGB, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kRootFile, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUAGA, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUAGB, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUBGA, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUBGB, kTestUserC, -1));

  KTEST_BEGIN("chown(): can change uid to same uid if owner (== euid)");
  KEXPECT_EQ(0, vfs_lchown(kUBGA, kTestUserB, -1));
  KEXPECT_EQ(0, vfs_lchown(kUBGB, kTestUserB, -1));
  KEXPECT_EQ(0, do_fchown(kUBGA, kTestUserB, -1));
  KEXPECT_EQ(0, do_fchown(kUBGB, kTestUserB, -1));

  KTEST_BEGIN("chown(): cannot change uid to same uid if not owner (== ruid)");
  KEXPECT_EQ(-EPERM, vfs_lchown(kUAGA, kTestUserA, -1));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUAGB, kTestUserA, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUAGA, kTestUserA, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUAGB, kTestUserA, -1));

  KTEST_BEGIN("chown(): cannot change uid to same uid if not owner (unrelated uid)");
  KEXPECT_EQ(-EPERM, vfs_lchown(kUCGA, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUCGB, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUCGA, kTestUserC, -1));
  KEXPECT_EQ(-EPERM, do_fchown(kUCGB, kTestUserC, -1));

  KTEST_BEGIN("chown(): cannot change gid to egid if not owner (== ruid)");
  KEXPECT_EQ(-EPERM, vfs_lchown(kUAGA, -1, kTestGroupB));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUAGB, -1, kTestGroupB));
  KEXPECT_EQ(-EPERM, do_fchown(kUAGA, -1, kTestGroupB));
  KEXPECT_EQ(-EPERM, do_fchown(kUAGB, -1, kTestGroupB));

  KTEST_BEGIN("chown(): cannot change gid to egid if not owner (unrelated uid)");
  KEXPECT_EQ(-EPERM, vfs_lchown(kUCGA, -1, kTestGroupB));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUCGB, -1, kTestGroupB));
  KEXPECT_EQ(-EPERM, do_fchown(kUCGA, -1, kTestGroupB));
  KEXPECT_EQ(-EPERM, do_fchown(kUCGB, -1, kTestGroupB));

  KTEST_BEGIN("chown(): can change gid to egid if owner (== euid)");
  KEXPECT_EQ(0, vfs_lchown(kUBGA, -1, kTestGroupB));
  KEXPECT_EQ(0, vfs_lchown(kUBGB, -1, kTestGroupB));
  EXPECT_OWNER_IS(kUBGA, kTestUserB, kTestGroupB);
  EXPECT_OWNER_IS(kUBGB, kTestUserB, kTestGroupB);
  KEXPECT_EQ(0, do_fchown(kUBGA, -1, kTestGroupB));
  KEXPECT_EQ(0, do_fchown(kUBGB, -1, kTestGroupB));
  EXPECT_OWNER_IS(kUBGA, kTestUserB, kTestGroupB);
  EXPECT_OWNER_IS(kUBGB, kTestUserB, kTestGroupB);

  // Test again with owner explicitly set.
  KEXPECT_EQ(0, vfs_lchown(kUBGA, kTestUserB, kTestGroupB));
  KEXPECT_EQ(0, vfs_lchown(kUBGB, kTestUserB, kTestGroupB));
  KEXPECT_EQ(0, do_fchown(kUBGA, kTestUserB, kTestGroupB));
  KEXPECT_EQ(0, do_fchown(kUBGB, kTestUserB, kTestGroupB));

  KTEST_BEGIN("chown(): cannot change gid to non-egid if owner (== euid)");
  KEXPECT_EQ(-EPERM, vfs_lchown(kUBGA, -1, kTestGroupA));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUBGB, -1, kTestGroupA));
  KEXPECT_EQ(-EPERM, do_fchown(kUBGA, -1, kTestGroupA));
  KEXPECT_EQ(-EPERM, do_fchown(kUBGB, -1, kTestGroupA));

  KEXPECT_EQ(-EPERM, vfs_lchown(kUBGA, -1, kTestGroupC));
  KEXPECT_EQ(-EPERM, vfs_lchown(kUBGB, -1, kTestGroupC));
  KEXPECT_EQ(-EPERM, do_fchown(kUBGA, -1, kTestGroupC));
  KEXPECT_EQ(-EPERM, do_fchown(kUBGB, -1, kTestGroupC));

  // TODO(aoates): test setting gid to a supplementary group ID.

  vfs_unlink(kRootFile);
  vfs_unlink(kUAGA);
  vfs_unlink(kUAGB);
  vfs_unlink(kUBGA);
  vfs_unlink(kUBGB);
  vfs_unlink(kUCGA);
  vfs_unlink(kUCGB);
}

// Do a basic lchown/fchown test for the given file.
#define BASIC_CHOWN_TEST(path, filetype) do { \
  KTEST_BEGIN("vfs_lchown(): " filetype); \
  EXPECT_OWNER_IS(path, 0, 0); \
  KEXPECT_EQ(0, vfs_lchown(path, kTestUserA, kTestGroupA)); \
  EXPECT_OWNER_IS(path, kTestUserA, kTestGroupA); \
\
  KTEST_BEGIN("vfs_fchown(): " filetype); \
  int fd = vfs_open(path, VFS_O_RDONLY); \
  KEXPECT_GE(fd, 0); \
  KEXPECT_EQ(0, vfs_fchown(fd, kTestUserB, kTestGroupB)); \
  EXPECT_OWNER_IS(path, kTestUserB, kTestGroupB); \
  KEXPECT_EQ(0, vfs_close(fd)); \
} while (0);

// TODO(aoates): rewrite fchown tests to use helper
static void lchown_test(void) {
  const kuid_t kTestUserA = 1;
  const kuid_t kTestUserB = 2;
  const kgid_t kTestGroupA = 3;
  const kgid_t kTestGroupB = 4;

  const char kDir[] = "chown_test_dir";
  const char kRegFile[] = "chown_test_dir/reg";
  const char kCharDevFile[] = "chown_test_dir/char";
  const char kBlockDevFile[] = "chown_test_dir/block";

  KTEST_BEGIN("vfs_lchown()/vfs_fchown(): test setup");
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));
  create_file(kRegFile, RWX);
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR, kmakedev(1, 2)));
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, kmakedev(3, 4)));

  KTEST_BEGIN("vfs_lchown(): bad arguments");
  KEXPECT_EQ(-EINVAL, vfs_lchown(0x0, -1, -1));
  KEXPECT_EQ(-EINVAL, vfs_lchown(kRegFile, -5, -1));
  KEXPECT_EQ(-EINVAL, vfs_lchown(kRegFile, -1, -5));

  KTEST_BEGIN("vfs_fchown(): bad arguments");
  int fd = vfs_open(kRegFile, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EBADF, vfs_fchown(-1, -1, -1));
  KEXPECT_EQ(-EINVAL, vfs_fchown(fd, -5, -1));
  KEXPECT_EQ(-EINVAL, vfs_fchown(fd, -1, -5));
  vfs_close(fd);
  KEXPECT_EQ(-EBADF, vfs_fchown(fd, -1, -1));

  // Regular fchown/lchown tests for each file type.
  BASIC_CHOWN_TEST(kRegFile, "regular file");
  BASIC_CHOWN_TEST(kDir, "directory");
  BASIC_CHOWN_TEST(kCharDevFile, "character device");
  BASIC_CHOWN_TEST(kBlockDevFile, "block device");

  // Only uid/gid tests.
  KTEST_BEGIN("vfs_lchown(): only setting uid");
  KEXPECT_EQ(0, vfs_lchown(kRegFile, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kRegFile, kTestUserB, -1));
  EXPECT_OWNER_IS(kRegFile, kTestUserB, kTestGroupA);

  KTEST_BEGIN("vfs_fchown(): only setting uid");
  fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fchown(fd, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_fchown(fd, kTestUserB, -1));
  EXPECT_OWNER_IS(kRegFile, kTestUserB, kTestGroupA);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_lchown(): only setting gid");
  KEXPECT_EQ(0, vfs_lchown(kRegFile, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kRegFile, -1, kTestGroupB));
  EXPECT_OWNER_IS(kRegFile, kTestUserA, kTestGroupB);

  KTEST_BEGIN("vfs_fchown(): only setting gid");
  fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fchown(fd, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_fchown(fd, -1, kTestGroupB));
  EXPECT_OWNER_IS(kRegFile, kTestUserA, kTestGroupB);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_lchown(): setting neither uid nor gid");
  KEXPECT_EQ(0, vfs_lchown(kRegFile, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kRegFile, -1, -1));
  EXPECT_OWNER_IS(kRegFile, kTestUserA, kTestGroupA);

  KTEST_BEGIN("vfs_fchown(): setting neither uid nor gid");
  fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fchown(fd, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_fchown(fd, -1, -1));
  EXPECT_OWNER_IS(kRegFile, kTestUserA, kTestGroupA);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_lchown(): setting uid/gid to 0");
  KEXPECT_EQ(0, vfs_lchown(kRegFile, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kRegFile, 0, 0));
  EXPECT_OWNER_IS(kRegFile, 0, 0);

  KTEST_BEGIN("vfs_fchown(): uid/gid to 0");
  fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fchown(fd, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_fchown(fd, 0, 0));
  EXPECT_OWNER_IS(kRegFile, 0, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  // Run tests as an unpriviledged user.
  kpid_t child_pid = proc_fork(&non_root_chown_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  KEXPECT_EQ(0, vfs_rmdir(kDir));

  // TODO(aoates): tests:
  //  * fchown/lchown resets ISUID/ISGID (if root and not root, only for
  //  executable files).
  //  * ISGID for non-group-executable file NOT reset.
  //  * maybe: fchown() with different fd flags? (RW vs RD_ONLY etc)
}

static void chown_test(void) {
  const kuid_t kTestUserA = 1;
  const kuid_t kTestUserB = 2;
  const kgid_t kTestGroupA = 3;
  const kgid_t kTestGroupB = 4;

  const char kDir[] = "chown_test_dir";
  const char kRegFile[] = "chown_test_dir/reg";
  const char kFileLink[] = "chown_test_dir/file_link";
  const char kDirLink[] = "chown_test_dir/dir_link";
  const char kBadLink[] = "chown_test_dir/bad_link";

  KTEST_BEGIN("vfs_chown(): test setup");
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));
  create_file(kRegFile, RWX);

  KTEST_BEGIN("vfs_chown(): bad arguments");
  KEXPECT_EQ(-EINVAL, vfs_chown(0x0, -1, -1));
  KEXPECT_EQ(-EINVAL, vfs_chown(kRegFile, -5, -1));
  KEXPECT_EQ(-EINVAL, vfs_chown(kRegFile, -1, -5));


  KTEST_BEGIN("vfs_chown(): regular file");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_chown(kRegFile, kTestUserB, kTestGroupB));
  KEXPECT_EQ(0, vfs_stat(kRegFile, &stat));
  KEXPECT_EQ(kTestUserB, stat.st_uid);
  KEXPECT_EQ(kTestGroupB, stat.st_gid);


  KTEST_BEGIN("vfs_chown(): link to regular file");
  KEXPECT_EQ(0, vfs_symlink("reg", kFileLink));
  KEXPECT_EQ(0, vfs_chown(kFileLink, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_stat(kRegFile, &stat));
  KEXPECT_EQ(kTestUserA, stat.st_uid);
  KEXPECT_EQ(kTestGroupA, stat.st_gid);

  KEXPECT_EQ(0, vfs_lstat(kFileLink, &stat));
  KEXPECT_EQ(SUPERUSER_UID, stat.st_uid);
  KEXPECT_EQ(SUPERUSER_GID, stat.st_gid);


  KTEST_BEGIN("vfs_chown(): link to directory");
  kmemset(&stat, 0, sizeof(apos_stat_t));
  KEXPECT_EQ(0, vfs_symlink(".", kDirLink));
  KEXPECT_EQ(0, vfs_chown(kDirLink, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_stat(kDir, &stat));
  KEXPECT_EQ(kTestUserA, stat.st_uid);
  KEXPECT_EQ(kTestGroupA, stat.st_gid);

  KEXPECT_EQ(0, vfs_lstat(kDirLink, &stat));
  KEXPECT_EQ(SUPERUSER_UID, stat.st_uid);
  KEXPECT_EQ(SUPERUSER_GID, stat.st_gid);


  KTEST_BEGIN("vfs_chown(): dangling symlink");
  kmemset(&stat, 0, sizeof(apos_stat_t));
  KEXPECT_EQ(0, vfs_symlink("bad", kBadLink));
  KEXPECT_EQ(-ENOENT, vfs_chown(kBadLink, kTestUserA, kTestGroupA));

  KEXPECT_EQ(0, vfs_lstat(kBadLink, &stat));
  KEXPECT_EQ(SUPERUSER_UID, stat.st_uid);
  KEXPECT_EQ(SUPERUSER_GID, stat.st_gid);


  vfs_unlink(kFileLink);
  vfs_unlink(kDirLink);
  vfs_unlink(kBadLink);
  vfs_unlink(kRegFile);
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

static void mode_flags_test(void) {
  KTEST_BEGIN("vfs kmode_t flags test");
  KEXPECT_EQ(VFS_S_IRWXU, VFS_S_IRUSR | VFS_S_IWUSR | VFS_S_IXUSR);
  KEXPECT_EQ(VFS_S_IRWXG, VFS_S_IRGRP | VFS_S_IWGRP | VFS_S_IXGRP);
  KEXPECT_EQ(VFS_S_IRWXO, VFS_S_IROTH | VFS_S_IWOTH | VFS_S_IXOTH);

  const kmode_t kUniqueFlags[] = {
    VFS_S_IRUSR, VFS_S_IWUSR, VFS_S_IXUSR, VFS_S_IRGRP, VFS_S_IWGRP,
    VFS_S_IXGRP, VFS_S_IROTH, VFS_S_IWOTH, VFS_S_IXOTH, VFS_S_ISUID,
    VFS_S_ISGID, VFS_S_ISVTX,
  };
  const int kNumUniqueFlags = sizeof(kUniqueFlags) / sizeof(kmode_t);

  for (int i = 0; i < kNumUniqueFlags; ++i) {
    int count = 0;
    for (int j = 0; j < kNumUniqueFlags; ++j) {
      if ((kUniqueFlags[i] & kUniqueFlags[j]) != 0) count++;
    }
    KEXPECT_EQ(1, count);
  }
}

// Do a basic chmod/fchmod test for the given file.
#define BASIC_CHMOD_TEST(path, filetype, mode_filetype) do { \
  KTEST_BEGIN("vfs_chmod(): " filetype); \
  KEXPECT_NE(VFS_S_IRWXO | mode_filetype, get_mode(path)); \
  KEXPECT_EQ(0, vfs_chmod(path, VFS_S_IRWXO)); \
  KEXPECT_EQ(VFS_S_IRWXO | mode_filetype, get_mode(path)); \
\
  KTEST_BEGIN("vfs_fchmod(): " filetype); \
  int fd = vfs_open(path, VFS_O_RDONLY); \
  KEXPECT_GE(fd, 0); \
  KEXPECT_NE(VFS_S_IRWXG | mode_filetype, get_mode(path)); \
  KEXPECT_EQ(0, vfs_fchmod(fd, VFS_S_IRWXG)); \
  KEXPECT_EQ(VFS_S_IRWXG | mode_filetype, get_mode(path)); \
  KEXPECT_EQ(0, vfs_close(fd)); \
\
  KTEST_BEGIN("vfs_chmod(): SUID/SGID/SVXT for " filetype); \
  KEXPECT_EQ(0, vfs_chmod(path, VFS_S_IRWXU | VFS_S_ISUID | \
                           VFS_S_ISGID | VFS_S_ISVTX)); \
  KEXPECT_EQ(VFS_S_IRWXU | VFS_S_ISUID | VFS_S_ISGID |  VFS_S_ISVTX | \
             mode_filetype, get_mode(path)); \
\
} while (0);

static void non_root_chmod_test_func(void* arg) {
  const kuid_t kTestUserA = 1;
  const kuid_t kTestUserB = 2;
  const kuid_t kTestGroupA = 4;
  const kuid_t kTestGroupB = 5;

  const char kRegFileA[] = "chmod_test_dir/regA";
  const char kRegFileB[] = "chmod_test_dir/regB";

  KTEST_BEGIN("vfs_chmod(): non-root test setup");
  create_file(kRegFileA, RWX);
  create_file(kRegFileB, RWX);
  KEXPECT_EQ(0, vfs_lchown(kRegFileA, kTestUserA, kTestGroupA));
  KEXPECT_EQ(0, vfs_lchown(kRegFileB, kTestUserB, kTestGroupB));

  KTEST_BEGIN("vfs_chmod(): root can always chmod");
  KEXPECT_EQ(0, vfs_chmod(kRegFileA, VFS_S_IRWXO));
  KEXPECT_EQ(VFS_S_IRWXO | VFS_S_IFREG, get_mode(kRegFileA));

  KEXPECT_EQ(0, setregid(kTestGroupA, kTestGroupB));
  KEXPECT_EQ(0, setreuid(kTestUserA, kTestUserB));

  KTEST_BEGIN("vfs_chmod(): non-root owner can chmod");
  KEXPECT_EQ(0, vfs_chmod(kRegFileB, VFS_S_IRUSR));
  KEXPECT_EQ(VFS_S_IRUSR | VFS_S_IFREG, get_mode(kRegFileB));

  KTEST_BEGIN("vfs_chmod(): non-owner cannot chmod");
  KEXPECT_EQ(-EPERM, vfs_chmod(kRegFileA, VFS_S_IRUSR));

  KEXPECT_EQ(0, vfs_unlink(kRegFileA));
  KEXPECT_EQ(0, vfs_unlink(kRegFileB));
}

static void chmod_test(void) {
  const char kDir[] = "chmod_test_dir";
  const char kRegFile[] = "chmod_test_dir/reg";
  const char kCharDevFile[] = "chmod_test_dir/char";
  const char kBlockDevFile[] = "chmod_test_dir/block";

  KTEST_BEGIN("vfs_chmod()/vfs_fchmod(): test setup");
  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));
  create_file(kRegFile, RWX);
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR, kmakedev(1, 2)));
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, kmakedev(3, 4)));

  KTEST_BEGIN("vfs_chmod(): invalid arguments test");
  KEXPECT_EQ(-EINVAL, vfs_chmod(0x0, VFS_S_IRWXU));
  KEXPECT_EQ(-EINVAL, vfs_chmod(kRegFile, 0xFFFFF));
  KEXPECT_EQ(-EINVAL, vfs_chmod(kRegFile, 0xFFFFF));
  KEXPECT_EQ(-ENOENT, vfs_chmod("chmod_test_dir/notafile", VFS_S_IRWXU));

  KTEST_BEGIN("vfs_fchmod(): invalid arguments test");
  int fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EBADF, vfs_fchmod(-1, VFS_S_IRWXU));
  KEXPECT_EQ(-EINVAL, vfs_fchmod(fd, 0xFFFFF));
  vfs_close(fd);
  KEXPECT_EQ(-EBADF, vfs_fchmod(fd, VFS_S_IRWXU));

  BASIC_CHMOD_TEST(kRegFile, "regular file", VFS_S_IFREG);
  BASIC_CHMOD_TEST(kDir, "directory", VFS_S_IFDIR);
  BASIC_CHMOD_TEST(kCharDevFile, "character device", VFS_S_IFCHR);
  BASIC_CHMOD_TEST(kBlockDevFile, "block device", VFS_S_IFBLK);

  KTEST_BEGIN("vfs_chmod(): decreasing permissions");
  KEXPECT_EQ(0,
             vfs_chmod(kRegFile, VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO |
                                     VFS_S_ISUID | VFS_S_ISGID | VFS_S_ISVTX));
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO |
             VFS_S_ISUID | VFS_S_ISGID | VFS_S_ISVTX, get_mode(kRegFile));
  KEXPECT_EQ(0, vfs_chmod(kRegFile, VFS_S_IRWXG | VFS_S_IRWXO));
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXG | VFS_S_IRWXO, get_mode(kRegFile));

  KTEST_BEGIN("vfs_chmod(): increasing permissions");
  KEXPECT_EQ(0, vfs_chmod(kRegFile, VFS_S_IRWXU));
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXU, get_mode(kRegFile));
  KEXPECT_EQ(0, vfs_chmod(kRegFile, VFS_S_IRWXG | VFS_S_IRWXO | VFS_S_ISUID |
                                        VFS_S_ISGID | VFS_S_ISVTX));
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXG | VFS_S_IRWXO |
             VFS_S_ISUID | VFS_S_ISGID | VFS_S_ISVTX, get_mode(kRegFile));

  KTEST_BEGIN("vfs_chmod(): keep same permissions");
  const kmode_t kAllPerms = VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO |
      VFS_S_ISUID | VFS_S_ISGID | VFS_S_ISVTX;
  KEXPECT_EQ(0, vfs_chmod(kRegFile, kAllPerms));
  KEXPECT_EQ(VFS_S_IFREG | kAllPerms, get_mode(kRegFile));
  KEXPECT_EQ(0, vfs_chmod(kRegFile, kAllPerms));
  KEXPECT_EQ(VFS_S_IFREG | kAllPerms, get_mode(kRegFile));

  // Run tests as an unpriviledged user.
  KEXPECT_EQ(0, vfs_chmod(kDir, VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));
  kpid_t child_pid = proc_fork(&non_root_chmod_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);

  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  KEXPECT_EQ(0, vfs_rmdir(kDir));

  // TODO(aoates): tests:
  //  * non-root changing the mode clears ISGID if groups don't match.
  //  * writing a regular file clears ISUID/ISGID
}

static void open_mode_test(void) {
  const char kDir[] = "open_with_mode_test";
  const char kRegFile[] = "open_with_mode_test/reg";

  KTEST_BEGIN("vfs_open(): O_CREAT with mode test setup");
  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  KTEST_BEGIN("vfs_open(): O_CREAT with mode test");
  int fd = vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, 0);
  KEXPECT_EQ(VFS_S_IFREG, get_mode(kRegFile));
  vfs_close(fd);
  vfs_unlink(kRegFile);

  fd = vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRUSR | VFS_S_ISUID);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRUSR | VFS_S_ISUID, get_mode(kRegFile));
  vfs_close(fd);
  vfs_unlink(kRegFile);

  KTEST_BEGIN("vfs_open(): O_CREAT with file type bits set");
  fd = vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, VFS_S_IFREG | VFS_S_IRUSR);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRUSR, get_mode(kRegFile));
  vfs_close(fd);
  vfs_unlink(kRegFile);
  fd = vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, VFS_S_IFDIR | VFS_S_IRUSR);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRUSR, get_mode(kRegFile));
  vfs_close(fd);
  vfs_unlink(kRegFile);

  KTEST_BEGIN("vfs_open(): O_CREAT with invalid mode test");
  KEXPECT_EQ(-EINVAL, vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, 0xFFFFF));
  KEXPECT_EQ(-EINVAL, vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, -1));

  KTEST_BEGIN("vfs_open(): O_CREAT with mode on existing file");
  fd = vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRUSR);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRUSR, get_mode(kRegFile));
  vfs_close(fd);

  fd = vfs_open(kRegFile, VFS_O_CREAT | VFS_O_RDWR, VFS_S_IRUSR | VFS_S_IRGRP);
  // Shouldn't have changed the mode.
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRUSR, get_mode(kRegFile));
  vfs_close(fd);

  KTEST_BEGIN("vfs_open(): open with mode on existing file, no O_CREAT");
  fd = vfs_open(kRegFile, VFS_O_RDWR, VFS_S_IRUSR | VFS_S_IRGRP);
  // Shouldn't have changed the mode.
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRUSR, get_mode(kRegFile));
  vfs_close(fd);

  vfs_unlink(kRegFile);
  KEXPECT_EQ(0, vfs_rmdir(kDir));
}

static void mkdir_mode_test(void) {
  const char kDir[] = "mkdir_mode_test";

  KTEST_BEGIN("vfs_mkdir(): invalid mode test");
  KEXPECT_EQ(-EINVAL, vfs_mkdir(kDir, -1));
  KEXPECT_EQ(-EINVAL, vfs_mkdir(kDir, 0x1ff00));

  KTEST_BEGIN("vfs_mkdir(): mode test");
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IRWXG | VFS_S_IRWXO | VFS_S_ISUID));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXG | VFS_S_IRWXO | VFS_S_ISUID,
             get_mode(kDir));
  vfs_rmdir(kDir);
  KTEST_BEGIN("vfs_mkdir(): mode test with file type bits");
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IFDIR | VFS_S_IRWXG | VFS_S_IRWXO));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXG | VFS_S_IRWXO, get_mode(kDir));
  vfs_rmdir(kDir);
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IFREG | VFS_S_IRWXG | VFS_S_IRWXO));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXG | VFS_S_IRWXO, get_mode(kDir));
  vfs_rmdir(kDir);

  KTEST_BEGIN("vfs_mkdir(): mode test w/ existing directory");
  KEXPECT_EQ(0, vfs_mkdir(kDir, VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST, vfs_mkdir(kDir, VFS_S_IRWXG));
  // Shouldn't have changed the mode.
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IRWXU, get_mode(kDir));
  vfs_rmdir(kDir);
}

static void mknod_mode_test(void) {
  const char kDir[] = "mknod_mode_test_dir";
  const char kRegFile[] = "mknod_mode_test_dir/reg";
  const char kCharDevFile[] = "mknod_mode_test_dir/char";
  const char kBlockDevFile[] = "mknod_mode_test_dir/block";

  KEXPECT_EQ(0, vfs_mkdir(kDir, 0));

  KTEST_BEGIN("mknod(): invalid mode test");
  KEXPECT_EQ(-EINVAL, vfs_mknod(kRegFile, VFS_S_IFREG | 0xffff, kmakedev(0, 0)));
  KEXPECT_EQ(-EINVAL, vfs_mknod(kRegFile, VFS_S_IFREG | -1, kmakedev(0, 0)));
  KEXPECT_EQ(-EINVAL, vfs_mknod(kRegFile, 0x200000, kmakedev(0, 0)));

  KTEST_BEGIN("mknod(): regular file w/ mode test");
  KEXPECT_EQ(0, vfs_mknod(kRegFile, VFS_S_IFREG | VFS_S_IRWXU, kmakedev(0, 0)));
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IRWXU, get_mode(kRegFile));

  KTEST_BEGIN("mknod(): character device file w/ mode test");
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR | VFS_S_IROTH,
                          kmakedev(0, 0)));
  KEXPECT_EQ(VFS_S_IFCHR | VFS_S_IROTH, get_mode(kCharDevFile));

  KTEST_BEGIN("mknod(): block device file w/ mode test");
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK | VFS_S_IXGRP,
                          kmakedev(0, 0)));
  KEXPECT_EQ(VFS_S_IFBLK | VFS_S_IXGRP, get_mode(kBlockDevFile));

  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  vfs_rmdir(kDir);
}

static void symlink_testA(void) {
  const int kBufSize = 100;
  char buf[kBufSize];
  int fd;

  KTEST_BEGIN("vfs_symlink(): symlink to file");
  KEXPECT_EQ(0, vfs_mkdir("symlink_test", VFS_S_IRWXU));
  create_file_with_data("symlink_test/file", "abcd");

  KEXPECT_EQ(0, vfs_symlink("file", "symlink_test/link_to_file"));

  fd = vfs_open("symlink_test/link_to_file", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    KEXPECT_EQ(4, vfs_read(fd, buf, kBufSize));
    buf[4] = '\0';
    KEXPECT_STREQ("abcd", buf);
    vfs_close(fd);
  }

  KTEST_BEGIN("vfs_symlink(): symlink to directory");
  KEXPECT_EQ(0, vfs_mkdir("symlink_test/dir", VFS_S_IRWXU));
  create_file("symlink_test/dir/file1", RWX);
  create_file("symlink_test/dir/file2", RWX);

  KEXPECT_EQ(0, vfs_symlink("dir", "symlink_test/link_to_dir"));
  KEXPECT_EQ(0, compare_dirents_p(
                    "symlink_test/link_to_dir", 4,
                    (edirent_t[]) {
                        {-1, "."}, {-1, ".."}, {-1, "file1"}, {-1, "file2"}}));

  KTEST_BEGIN("vfs_symlink(): symlink to directory (in middle of path)");
  fd = vfs_open("symlink_test/link_to_dir/file1", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  KEXPECT_EQ(0, vfs_symlink("..", "symlink_test/link_to_dir2"));
  KEXPECT_EQ(
      0,
      compare_dirents_p(
          "symlink_test/link_to_dir2/symlink_test/link_to_dir2/./symlink_test/"
          "dir",
          4,
          (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "file1"}, {-1, "file2"}}));

  KTEST_BEGIN("vfs_symlink(): symlink over existing file/dir/etc");
  KEXPECT_EQ(0, vfs_symlink("not_a_file", "symlink_test/bad_link1"));
  KEXPECT_EQ(0, vfs_symlink("../bad/bath", "symlink_test/bad_link2"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "/"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "symlink_test/link_to_file"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "symlink_test/link_to_dir"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "symlink_test/file"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "symlink_test/dir"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "symlink_test/bad_link1"));
  KEXPECT_EQ(-EEXIST, vfs_symlink("dir", "symlink_test/bad_link2"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/bad_link1"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/bad_link2"));

  KTEST_BEGIN("vfs_symlink(): symlink at bad path");
  KEXPECT_EQ(-ENOENT, vfs_symlink("dir", "noent/dir/x"));
  KEXPECT_EQ(-ENOENT, vfs_symlink("dir", "symlink_test/dir2/x"));
  KEXPECT_EQ(-ENOTDIR, vfs_symlink("dir", "symlink_test/file/x"));

  KTEST_BEGIN("vfs_symlink(): symlink pointing to bad path");
  KEXPECT_EQ(0, vfs_symlink("../bad/path", "symlink_test/bad_link"));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1",
                               VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1/d2", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1/d2",
                               VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/bad_link"));

  KTEST_BEGIN(
      "vfs_symlink(): symlink pointing to bad path (only last element bad)");
  KEXPECT_EQ(0, vfs_symlink("../bad", "symlink_test/bad_link"));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1",
                               VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1/d2", VFS_O_RDONLY));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/bad_link/d1/d2",
                               VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/bad_link"));
}

static void symlink_testB(void) {
  const int kBufSize = 100;
  char buf[kBufSize];
  int fd;

  KTEST_BEGIN("vfs_symlink(): invalid arguments");
  // TODO(aoates): test too-long paths
  KEXPECT_EQ(-EINVAL, vfs_symlink(0x0, "symlink_test/bad_link"));
  KEXPECT_EQ(-EINVAL, vfs_symlink("symlink_test/bad_link", 0x0));


  KTEST_BEGIN("vfs_symlink(): symlink to another symlink");
  KEXPECT_EQ(0,
             vfs_symlink("link_to_file", "symlink_test/link_to_link_to_file"));

  fd = vfs_open("symlink_test/link_to_link_to_file", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    KEXPECT_EQ(4, vfs_read(fd, buf, kBufSize));
    buf[4] = '\0';
    KEXPECT_STREQ("abcd", buf);
    vfs_close(fd);
  }

  KTEST_BEGIN(
      "vfs_symlink(): symlink to another symlink (in different directory)");
  KEXPECT_EQ(0, vfs_mkdir("symlink_test/dir1", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("symlink_test/dir1/dir2", VFS_S_IRWXU));
  create_file("symlink_test/dir1/dir2/f", RWX);
  KEXPECT_EQ(0, vfs_symlink("f", "symlink_test/dir1/dir2/link"));
  KEXPECT_EQ(0, vfs_symlink("dir2/link", "symlink_test/dir1/link2"));
  EXPECT_FILE_EXISTS("symlink_test/dir1/link2");
  KEXPECT_EQ(0, vfs_unlink("symlink_test/dir1/dir2/f"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/dir1/dir2/link"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/dir1/link2"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test/dir1/dir2"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test/dir1"));


  KTEST_BEGIN("vfs_symlink(): long symlinks");
  const char kPath58[] =
      "./././././././././././././././././././././././././././file";
  const char kPath59[] =
      "./././././././././././././././././././././././././././/file";
  const char kPath60[] =
      "././././././././././././././././././././././././././././file";
  const char kPath61[] =
      "././././././././././././././././././././././././././././/file";
  KEXPECT_EQ(58, kstrlen(kPath58));
  KEXPECT_EQ(59, kstrlen(kPath59));
  KEXPECT_EQ(60, kstrlen(kPath60));
  KEXPECT_EQ(61, kstrlen(kPath61));

  KEXPECT_EQ(0, vfs_symlink(kPath58, "symlink_test/link58"));
  KEXPECT_EQ(0, vfs_symlink(kPath59, "symlink_test/link59"));
  KEXPECT_EQ(0, vfs_symlink(kPath60, "symlink_test/link60"));
  KEXPECT_EQ(0, vfs_symlink(kPath61, "symlink_test/link61"));

  EXPECT_FILE_EXISTS("symlink_test/link58");
  EXPECT_FILE_EXISTS("symlink_test/link59");
  EXPECT_FILE_EXISTS("symlink_test/link60");
  EXPECT_FILE_EXISTS("symlink_test/link61");

  {
    char* very_long_path = kmalloc(1025);
    for (int i = 0; i < 1020; i += 2) {
      very_long_path[i] = '.';
      very_long_path[i + 1] = '/';
    }
    very_long_path[1020] = 'f';
    very_long_path[1021] = 'i';
    very_long_path[1022] = 'l';
    very_long_path[1023] = 'e';
    very_long_path[1024] = '\0';
    KEXPECT_EQ(0, vfs_symlink(very_long_path, "symlink_test/link_long"));
    EXPECT_FILE_EXISTS("symlink_test/link_long");
    kfree(very_long_path);
  }

  KEXPECT_EQ(0, vfs_unlink("symlink_test/link58"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link59"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link60"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link61"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link_long"));
}

static void symlink_testC(void) {
  KTEST_BEGIN("vfs_mkdir(): doesn't follow final symlink");
  KEXPECT_EQ(0, vfs_symlink("newdir", "symlink_test/mkdir_link"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("symlink_test/mkdir_link", VFS_S_IRWXU));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/newdir", VFS_O_RDONLY));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/mkdir_link"));


  KTEST_BEGIN("vfs_mknod(): doesn't follow final symlink");
  KEXPECT_EQ(0, vfs_symlink("newnode", "symlink_test/mknod_link"));
  KEXPECT_EQ(-EEXIST, vfs_mknod("symlink_test/mknod_link",
                                VFS_S_IFREG | VFS_S_IRWXU, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/newnode", VFS_O_RDONLY));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/mknod_link"));


  KTEST_BEGIN("vfs_rmdir(): doesn't follow final symlink");
  KEXPECT_EQ(0, vfs_mkdir("symlink_test/rmdir_dir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("rmdir_dir", "symlink_test/rmdir_link"));
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("symlink_test/rmdir_link"));
  EXPECT_FILE_EXISTS("symlink_test/rmdir_dir");
  KEXPECT_EQ(0, vfs_unlink("symlink_test/rmdir_link"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test/rmdir_dir"));


  KTEST_BEGIN("vfs_unlink(): doesn't follow final symlink");
  create_file("symlink_test/unlink_file", RWX);
  KEXPECT_EQ(0, vfs_symlink("unlink_file", "symlink_test/unlink_link"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/unlink_link"));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/unlink_link", VFS_S_IRWXU));
  EXPECT_FILE_EXISTS("symlink_test/unlink_file");
  KEXPECT_EQ(0, vfs_unlink("symlink_test/unlink_file"));


  KTEST_BEGIN("vfs_lstat(): doesn't follow final symlink");
  create_file("symlink_test/stat_file", RWX);
  KEXPECT_EQ(0, vfs_symlink("stat_file", "symlink_test/stat_link"));
  KEXPECT_NE(vfs_get_vnode_for_path("symlink_test/stat_file"),
             vfs_get_vnode_for_path("symlink_test/stat_link"));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_link", &stat));
  KEXPECT_EQ(vfs_get_vnode_for_path("symlink_test/stat_link"), stat.st_ino);
  KEXPECT_EQ(VFS_S_IFLNK, stat.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("symlink_test/stat_file"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/stat_link"));
}

static void symlink_testD(void) {
  apos_stat_t stat;

  KTEST_BEGIN("vfs_chdir(): follows final symlink");
  KEXPECT_EQ(0, vfs_mkdir("symlink_test/chdir_dir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("chdir_dir", "symlink_test/chdir_link"));
  KEXPECT_EQ(0, vfs_chdir("symlink_test/chdir_link"));

  char* cwd = kmalloc(VFS_MAX_PATH_LENGTH);
  int cwd_len = vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH);
  KEXPECT_GE(cwd_len, kstrlen("symlink_test/chdir_dir"));
  KEXPECT_STREQ("symlink_test/chdir_dir",
                cwd + (cwd_len - kstrlen("symlink_test/chdir_dir")));

  KEXPECT_EQ(0, vfs_chdir("../.."));

  KEXPECT_EQ(0, vfs_unlink("symlink_test/chdir_link"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test/chdir_dir"));


  KTEST_BEGIN("vfs_chdir(): doesn't follow symlink to non-directory");
  create_file("symlink_test/chdir_file", RWX);
  KEXPECT_EQ(0, vfs_symlink("chdir_file", "symlink_test/chdir_link"));
  KEXPECT_EQ(-ENOTDIR, vfs_chdir("symlink_test/chdir_link"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/chdir_link"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/chdir_file"));


  KTEST_BEGIN("vfs_lchown(): doesn't follow final symlink");
  create_file("symlink_test/stat_file", RWX);
  KEXPECT_EQ(0, vfs_symlink("stat_file", "symlink_test/stat_link"));

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_file", &stat));
  const kuid_t orig_file_owner = stat.st_uid;

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_link", &stat));
  KEXPECT_EQ(orig_file_owner, stat.st_uid);

  KEXPECT_EQ(0, vfs_lchown("symlink_test/stat_link", orig_file_owner + 1, -1));

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_file", &stat));
  KEXPECT_EQ(orig_file_owner, stat.st_uid);

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_link", &stat));
  KEXPECT_EQ(orig_file_owner + 1, stat.st_uid);

  KEXPECT_EQ(0, vfs_unlink("symlink_test/stat_file"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/stat_link"));


  KTEST_BEGIN("vfs_chmod(): follows final symlink");
  create_file("symlink_test/stat_file", "rwx------");
  KEXPECT_EQ(0, vfs_symlink("stat_file", "symlink_test/stat_link"));

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_file", &stat));
  const kmode_t orig_file_mode = stat.st_mode & ~VFS_S_IFMT;

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_link", &stat));
  KEXPECT_NE(stat.st_mode & ~VFS_S_IFMT, orig_file_mode | VFS_S_IRWXO);

  KEXPECT_EQ(0,
             vfs_chmod("symlink_test/stat_link", orig_file_mode | VFS_S_IRWXO));

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_file", &stat));
  KEXPECT_EQ(orig_file_mode | VFS_S_IRWXO, stat.st_mode & ~VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_lstat("symlink_test/stat_link", &stat));
  KEXPECT_EQ(VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
             stat.st_mode & ~VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("symlink_test/stat_file"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/stat_link"));

  kfree(cwd);
}

static void symlink_testE(void) {
  apos_stat_t stat;
  int fd;

  KTEST_BEGIN(
      "vfs_symlink(): vfs_open(O_CREAT) on symlink creates destination");
  KEXPECT_EQ(0, vfs_symlink("doesnt_exist", "symlink_test/creat_link"));
  KEXPECT_EQ(-ENOENT, vfs_open("symlink_test/creat_link", VFS_O_RDWR));
  fd = vfs_open("symlink_test/creat_link", VFS_O_RDWR | VFS_O_CREAT,
                VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(4, vfs_write(fd, "abcd", 4));
  KEXPECT_EQ(0, vfs_close(fd));
  EXPECT_FILE_EXISTS("symlink_test/creat_link");
  KEXPECT_EQ(0, vfs_unlink("symlink_test/doesnt_exist"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/creat_link"));

  KTEST_BEGIN("vfs_symlink(): symlink loop");
  KEXPECT_EQ(0, vfs_symlink("linkB", "symlink_test/linkA"));
  KEXPECT_EQ(0, vfs_symlink("linkA", "symlink_test/linkB"));
  KEXPECT_EQ(0, vfs_symlink("../symlink_test/linkD", "symlink_test/linkC"));
  KEXPECT_EQ(0, vfs_symlink("../symlink_test/linkC", "symlink_test/linkD"));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkA", VFS_O_RDWR));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkA/d1", VFS_O_RDWR));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkA/d1/d2", VFS_O_RDWR));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkB", VFS_O_RDWR));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkC", VFS_O_RDWR));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkD", VFS_O_RDWR));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkA"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkB"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkC"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkD"));

  KEXPECT_EQ(0, vfs_symlink("linkE/d1", "symlink_test/linkF"));
  KEXPECT_EQ(0, vfs_symlink("linkF/d1", "symlink_test/linkE"));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkE", VFS_O_RDWR));
  KEXPECT_EQ(-ELOOP, vfs_open("symlink_test/linkE/d1", VFS_O_RDWR));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkE"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkF"));


  KTEST_BEGIN("vfs_symlink(): create symlink in symlink'd directory");
  KEXPECT_EQ(0, vfs_mkdir("symlink_test/linkeddir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("linkeddir", "symlink_test/link"));
  KEXPECT_EQ(0, vfs_symlink("entry", "symlink_test/link/link2"));
  KEXPECT_EQ(0, compare_dirents_p(
                    "symlink_test/linkeddir", 3,
                    (edirent_t[]) {{-1, "."}, {-1, ".."}, {-1, "link2"}}));

  KEXPECT_EQ(0, vfs_unlink("symlink_test/linkeddir/link2"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test/linkeddir"));


  KTEST_BEGIN("vfs_symlink(): symlink to absolute path");
  char* cwd = kmalloc(VFS_MAX_PATH_LENGTH);
  KEXPECT_LE(0, vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH));
  char* link = kmalloc(VFS_MAX_PATH_LENGTH + 1);
  char* target = kmalloc(VFS_MAX_PATH_LENGTH + 1);
  kstrcpy(link, cwd);
  kstrcat(link, "/symlink_test/absolute_link");
  kstrcpy(target, cwd);
  kstrcat(target, "/symlink_test/file");

  KEXPECT_EQ(0, vfs_symlink(target, link));
  EXPECT_FILE_EXISTS(link);

  KEXPECT_EQ(0, vfs_unlink(link));


  KTEST_BEGIN("vfs_symlink(): initial symlink mode");
  KEXPECT_EQ(0, vfs_symlink("file", "symlink_test/modelink"));
  KEXPECT_EQ(0, vfs_lstat("symlink_test/modelink", &stat));
  KEXPECT_EQ(VFS_S_IFLNK | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
             stat.st_mode);
  KEXPECT_EQ(0, vfs_unlink("symlink_test/modelink"));

  KTEST_BEGIN("vfs_symlink(): test cleanup");
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link_to_link_to_file"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link_to_file"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/file"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link_to_dir"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/link_to_dir2"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/dir/file1"));
  KEXPECT_EQ(0, vfs_unlink("symlink_test/dir/file2"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test/dir"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_test"));

  kfree(cwd);
  kfree(link);
  kfree(target);
}

static void* vfs_swap_test_helper(void* arg) {
  // TODO(aoates): use spinlock, mutex, or notification.
  const bool* done = (const bool*)arg;
  while (!(*done)) {
    KEXPECT_EQ(0, vfs_unlink("symlink_swap_test/target"));
    KEXPECT_EQ(0, vfs_symlink("file2", "symlink_swap_test/target"));
    scheduler_yield();
    KEXPECT_EQ(0, vfs_unlink("symlink_swap_test/target"));
    KEXPECT_EQ(0,
               vfs_link("symlink_swap_test/file1", "symlink_swap_test/target"));
    scheduler_yield();
  }
  return NULL;
}

static void vfs_open_symlink_swap_test(void) {
  KTEST_BEGIN("vfs: file replaced with symlink during open()");
  // Setup two files that will stay put.  Link the first file and a create a
  // symlink to that linked version.
  KEXPECT_EQ(0, vfs_mkdir("symlink_swap_test", VFS_S_IRWXU));
  create_file_with_data("symlink_swap_test/file1", "");
  create_file_with_data("symlink_swap_test/file2", "");
  KEXPECT_EQ(0,
             vfs_link("symlink_swap_test/file1", "symlink_swap_test/target"));
  KEXPECT_EQ(0, vfs_symlink("target", "symlink_swap_test/link"));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("symlink_swap_test/file1", &stat));
  const apos_ino_t file1_ino = stat.st_ino;
  KEXPECT_EQ(0, vfs_stat("symlink_swap_test/file2", &stat));
  const apos_ino_t file2_ino = stat.st_ino;

  kthread_t thread1, thread2;
  chaos_args_t args;
  args.path = "symlink_swap_test";
  args.done = false;
  KEXPECT_EQ(0,
             proc_thread_create(&thread1, &vfs_swap_test_helper, &args.done));
  KEXPECT_EQ(0, proc_thread_create(&thread2, &chaos_helper, &args));
  const int kIters = 100 * CONCURRENCY_TEST_ITERS_MULT;
  for (int i = 0; i < kIters; ++i) {
    if (i % 3 == 0) scheduler_yield();
    int fd = vfs_open("symlink_swap_test/link", VFS_O_RDONLY);
    // ENOENT is fine, if we happened to catch between the link/symlink steps.
    if (fd == -ENOENT) continue;
    KEXPECT_GE(fd, 0);
    KEXPECT_EQ(0, vfs_fstat(fd, &stat));
    // Otherwise, we should always see either file1 or file2.
    if (stat.st_ino != file1_ino) {
      KEXPECT_EQ(file2_ino, stat.st_ino);
    } else {
      KEXPECT_EQ(file1_ino, stat.st_ino);
    }
    KEXPECT_EQ(0, vfs_close(fd));
  }

  args.done = true;
  kthread_join(thread1);
  kthread_join(thread2);

  KEXPECT_EQ(0, vfs_unlink("symlink_swap_test/link"));
  KEXPECT_EQ(0, vfs_unlink("symlink_swap_test/target"));
  KEXPECT_EQ(0, vfs_unlink("symlink_swap_test/file1"));
  KEXPECT_EQ(0, vfs_unlink("symlink_swap_test/file2"));
  KEXPECT_EQ(0, vfs_rmdir("symlink_swap_test"));
}

static void symlink_test(void) {
  symlink_testA();
  symlink_testB();
  symlink_testC();
  symlink_testD();
  symlink_testE();
  vfs_open_symlink_swap_test();
}

static void readlink_test(void) {
  const int kBufSize = 200;
  char buf[kBufSize];

  KTEST_BEGIN("vfs_readlink(): test setup");
  KEXPECT_EQ(0, vfs_mkdir("readlink_test", VFS_S_IRWXU));


  KTEST_BEGIN("vfs_readlink(): basic link");
  KEXPECT_EQ(0, vfs_symlink("target", "readlink_test/link"));
  kmemset(buf, 0, kBufSize);
  KEXPECT_EQ(6, vfs_readlink("readlink_test/link", buf, kBufSize));
  KEXPECT_STREQ("target", buf);


  KTEST_BEGIN("vfs_readlink(): doesn't append null");
  kmemset(buf, 'x', kBufSize);
  KEXPECT_EQ(6, vfs_readlink("readlink_test/link", buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp("targetxxxx", buf, 10));


  KTEST_BEGIN("vfs_readlink(): buffer too small");
  kmemset(buf, 'x', kBufSize);
  KEXPECT_EQ(3, vfs_readlink("readlink_test/link", buf, 3));
  KEXPECT_EQ(0, kstrncmp("tarxxxxxxx", buf, 10));


  KTEST_BEGIN("vfs_readlink(): invalid arguments");
  KEXPECT_EQ(-EINVAL, vfs_readlink("readlink_test/link", buf, -1));
  KEXPECT_EQ(-EINVAL, vfs_readlink("readlink_test/link", buf, INT_MAX));
  KEXPECT_EQ(-EINVAL, vfs_readlink("readlink_test/link", 0x0, kBufSize));
  KEXPECT_EQ(-EINVAL, vfs_readlink(0x0, buf, kBufSize));
  KEXPECT_EQ(-ENOENT, vfs_readlink("doesnt_exist", buf, kBufSize));
  KEXPECT_EQ(-ENOENT,
             vfs_readlink("readlink_test/doesnt_exist", buf, kBufSize));

  KEXPECT_EQ(-EINVAL, vfs_readlink("/", buf, kBufSize));
  KEXPECT_EQ(-EINVAL, vfs_readlink("/.", buf, kBufSize));
  KEXPECT_EQ(-EINVAL, vfs_readlink("readlink_test", buf, kBufSize));
  KEXPECT_EQ(-EINVAL, vfs_readlink("readlink_test/./.", buf, kBufSize));

  create_file("readlink_test/file", "rwxrwxrwx");
  KEXPECT_EQ(-EINVAL, vfs_readlink("readlink_test/file", buf, kBufSize));
  KEXPECT_EQ(-ENOTDIR, vfs_readlink("readlink_test/file/link", buf, kBufSize));
  KEXPECT_EQ(0, vfs_unlink("readlink_test/file"));

  KTEST_BEGIN("vfs_readlink(): test cleanup");
  KEXPECT_EQ(0, vfs_unlink("readlink_test/link"));
  KEXPECT_EQ(0, vfs_rmdir("readlink_test"));
}

static void dup_test(void) {
  KTEST_BEGIN("vfs_dup(): basic test");
  KEXPECT_EQ(0, vfs_mkdir("dup_test", 0));
  create_file_with_data("dup_test/file", "abcd");

  int fd1 = vfs_open("dup_test/file", VFS_O_RDONLY);
  KEXPECT_GE(fd1, 0);
  EXPECT_VNODE_REFCOUNT(1, "dup_test/file");

  int fd2 = vfs_dup(fd1);
  KEXPECT_GE(fd2, 0);
  KEXPECT_NE(fd1, fd2);
  EXPECT_VNODE_REFCOUNT(1, "dup_test/file");

  // Do a white-box test.
  file_t* file1, *file2;
  KEXPECT_EQ(0, lookup_fd(fd1, &file1));
  KEXPECT_EQ(0, lookup_fd(fd2, &file2));
  KEXPECT_EQ(file1, file2);
  KEXPECT_EQ(4, refcount_get(&file1->refcount));
  file_unref(file1);
  file_unref(file2);
  KEXPECT_EQ(2, refcount_get(&file1->refcount));

  char c;
  KEXPECT_EQ(1, vfs_read(fd1, &c, 1));
  KEXPECT_EQ('a', c);

  KEXPECT_EQ(1, vfs_read(fd2, &c, 1));
  KEXPECT_EQ('b', c);

  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(1, vfs_read(fd2, &c, 1));
  KEXPECT_EQ('c', c);

  KEXPECT_EQ(1, get_file_refcount(fd2));
  KEXPECT_EQ(0, vfs_close(fd2));

  EXPECT_VNODE_REFCOUNT(0, "dup_test/file");

  KTEST_BEGIN("vfs_dup(): bad file descriptor");
  KEXPECT_EQ(-EBADF, vfs_dup(-5));
  KEXPECT_EQ(-EBADF, vfs_dup(PROC_MAX_FDS + 1));

  KTEST_BEGIN("vfs_dup(): out of file descriptors");
  int all_fds[PROC_MAX_FDS];
  for (int i = 0; i < PROC_MAX_FDS; ++i) all_fds[i] = -1;
  int i = 0;
  do {
    fd1 = vfs_open("dup_test/file", VFS_O_RDONLY);
    if (fd1 >= 0)
      all_fds[i++] = fd1;
  } while (fd1 >= 0);

  KEXPECT_EQ(-EMFILE, fd1);
  KEXPECT_GE(all_fds[0], 0);
  KEXPECT_EQ(-EMFILE, vfs_dup(all_fds[0]));

  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (all_fds[i] >= 0) vfs_close(all_fds[i]);
  }

  KTEST_BEGIN("vfs_dup() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("dup_test/file"));
  KEXPECT_EQ(0, vfs_rmdir("dup_test"));
}

static void dup2_test(void) NO_THREAD_SAFETY_ANALYSIS {
  KTEST_BEGIN("vfs_dup2(): basic test");
  KEXPECT_EQ(0, vfs_mkdir("dup2_test", 0));
  create_file_with_data("dup2_test/file", "abcd");
  create_file_with_data("dup2_test/file2", "ABCD");

  int fd1 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  KEXPECT_GE(fd1, 0);
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");

  // Use vfs_dup() to get an fd we think is free.
  int fd2 = vfs_dup(fd1);
  KEXPECT_GE(fd2, 0);
  KEXPECT_NE(fd1, fd2);
  KEXPECT_EQ(0, vfs_close(fd2));

  // dup2() into the fd we just closed.
  KEXPECT_EQ(fd2, vfs_dup2(fd1, fd2));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");

  // Do a white-box test.
  file_t* file1, *file2;
  KEXPECT_EQ(0, lookup_fd(fd1, &file1));
  KEXPECT_EQ(0, lookup_fd(fd2, &file2));
  KEXPECT_EQ(file1, file2);
  KEXPECT_EQ(4, refcount_get(&file1->refcount));
  file_unref(file1);
  file_unref(file2);

  char c;
  KEXPECT_EQ(1, vfs_read(fd1, &c, 1));
  KEXPECT_EQ('a', c);

  KEXPECT_EQ(1, vfs_read(fd2, &c, 1));
  KEXPECT_EQ('b', c);

  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(1, vfs_read(fd2, &c, 1));
  KEXPECT_EQ('c', c);

  KEXPECT_EQ(1, get_file_refcount(fd2));
  KEXPECT_EQ(0, vfs_close(fd2));

  EXPECT_VNODE_REFCOUNT(0, "dup2_test/file");


  KTEST_BEGIN("vfs_dup2(): fd1 == fd2");
  fd1 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  KEXPECT_EQ(fd1, vfs_dup2(fd1, fd1));
  KEXPECT_EQ(1, get_file_refcount(fd1));
  KEXPECT_EQ(0, vfs_close(fd1));
  EXPECT_VNODE_REFCOUNT(0, "dup2_test/file");


  KTEST_BEGIN("vfs_dup2(): fd2 exists (different file)");
  fd1 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  fd2 = vfs_open("dup2_test/file2", VFS_O_RDONLY);
  KEXPECT_EQ(1, get_file_refcount(fd1));
  KEXPECT_EQ(1, get_file_refcount(fd2));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file2");

  KEXPECT_EQ(fd2, vfs_dup2(fd1, fd2));
  KEXPECT_EQ(proc_current()->fds[fd1].file, proc_current()->fds[fd2].file);
  KEXPECT_EQ(proc_current()->fds[fd1].flags, proc_current()->fds[fd2].flags);
  KEXPECT_EQ(2, get_file_refcount(fd1));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");
  EXPECT_VNODE_REFCOUNT(0, "dup2_test/file2");
  KEXPECT_EQ(0, vfs_close(fd1));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");
  KEXPECT_EQ(0, vfs_close(fd2));
  EXPECT_VNODE_REFCOUNT(0, "dup2_test/file");


  KTEST_BEGIN("vfs_dup2(): fd2 exists (same file)");
  fd1 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  fd2 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  KEXPECT_EQ(1, get_file_refcount(fd1));
  EXPECT_VNODE_REFCOUNT(2, "dup2_test/file");
  KEXPECT_NE(proc_current()->fds[fd1].file, proc_current()->fds[fd2].file);

  KEXPECT_EQ(fd2, vfs_dup2(fd1, fd2));
  KEXPECT_EQ(proc_current()->fds[fd1].file, proc_current()->fds[fd2].file);
  KEXPECT_EQ(2, get_file_refcount(fd1));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");
  KEXPECT_EQ(0, vfs_close(fd1));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");
  KEXPECT_EQ(0, vfs_close(fd2));
  EXPECT_VNODE_REFCOUNT(0, "dup2_test/file");


  KTEST_BEGIN("vfs_dup2(): fd2 exists (already duplicate)");
  fd1 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  fd2 = vfs_dup(fd1);
  KEXPECT_EQ(2, get_file_refcount(fd1));

  KEXPECT_EQ(fd2, vfs_dup2(fd1, fd2));
  KEXPECT_EQ(proc_current()->fds[fd1].file, proc_current()->fds[fd2].file);
  KEXPECT_EQ(2, get_file_refcount(fd2));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");
  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(1, get_file_refcount(fd2));
  EXPECT_VNODE_REFCOUNT(1, "dup2_test/file");
  KEXPECT_EQ(0, vfs_close(fd2));
  EXPECT_VNODE_REFCOUNT(0, "dup2_test/file");


  KTEST_BEGIN("vfs_dup2(): bad file descriptor (fd1)");
  fd1 = vfs_open("dup2_test/file", VFS_O_RDONLY);
  int orig_fd1_idx = proc_current()->fds[fd1].file;
  KEXPECT_EQ(-EBADF, vfs_dup2(-5, fd1));
  KEXPECT_EQ(-EBADF, vfs_dup2(PROC_MAX_FDS + 1, fd1));
  int unused_fd = 0;
  for (unused_fd = 0; unused_fd < PROC_MAX_FDS; ++unused_fd) {
    if (proc_current()->fds[unused_fd].file == PROC_UNUSED_FD) break;
  }
  KEXPECT_LT(unused_fd, PROC_MAX_FDS);
  KEXPECT_EQ(-EBADF, vfs_dup2(unused_fd, fd1));
  KEXPECT_EQ(-EBADF, vfs_dup2(unused_fd, unused_fd));
  KEXPECT_EQ(PROC_UNUSED_FD, proc_current()->fds[unused_fd].file);
  KEXPECT_EQ(orig_fd1_idx, proc_current()->fds[fd1].file);

  KTEST_BEGIN("vfs_dup2(): bad file descriptor (fd2)");
  KEXPECT_EQ(-EBADF, vfs_dup2(-5, -5));
  KEXPECT_EQ(-EBADF, vfs_dup2(fd1, -5));
  KEXPECT_EQ(-EBADF, vfs_dup2(fd1, PROC_MAX_FDS + 1));
  KEXPECT_EQ(orig_fd1_idx, proc_current()->fds[fd1].file);
  vfs_close(fd1);


  KTEST_BEGIN("vfs_dup2() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("dup2_test/file"));
  KEXPECT_EQ(0, vfs_unlink("dup2_test/file2"));
  KEXPECT_EQ(0, vfs_rmdir("dup2_test"));

  // TODO(aoates): test vfs_dup2() when closing the second file descriptor fails
}

static void pipe_test(void) {
  KTEST_BEGIN("vfs_pipe(): basic test");
  int fds[2];
  KEXPECT_EQ(0, vfs_pipe(fds));
  KEXPECT_GE(fds[0], 0);
  KEXPECT_GE(fds[1], 0);

  KEXPECT_EQ(5, vfs_write(fds[1], "abcde", 5));

  char buf[10];
  KEXPECT_EQ(5, vfs_read(fds[0], buf, 10));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  vfs_close(fds[0]);
  vfs_close(fds[1]);


  KTEST_BEGIN("vfs_pipe(): read and write on wrong ends");
  KEXPECT_EQ(0, vfs_pipe(fds));
  KEXPECT_EQ(-EBADF, vfs_write(fds[0], "abcde", 5));
  KEXPECT_EQ(-EBADF, vfs_read(fds[1], buf, 5));


  KTEST_BEGIN("vfs_pipe(): dup() pipe fd");
  int other_read = vfs_dup(fds[0]);
  KEXPECT_GE(other_read, 0);
  KEXPECT_EQ(5, vfs_write(fds[1], "abcde", 5));
  KEXPECT_EQ(3, vfs_read(fds[0], buf, 3));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(2, vfs_read(other_read, buf, 10));
  buf[2] = '\0';
  KEXPECT_STREQ("de", buf);

  vfs_close(other_read);


  KTEST_BEGIN("vfs_pipe(): stat pipe fd");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fds[0], &stat));
  KEXPECT_EQ(0, vfs_fstat(fds[1], &stat));
  // TODO(aoates): what should the other mode bits be?
  KEXPECT_EQ(1, VFS_S_ISFIFO(stat.st_mode));
  // TODO(aoates): test the other stat fields.


  KTEST_BEGIN("vfs_pipe(): vfs_seek() on pipe fd");
  KEXPECT_EQ(-ESPIPE, vfs_seek(fds[0], 0, VFS_SEEK_SET));
  KEXPECT_EQ(-ESPIPE, vfs_seek(fds[0], 5, VFS_SEEK_SET));
  KEXPECT_EQ(-ESPIPE, vfs_seek(fds[1], 0, VFS_SEEK_SET));
  KEXPECT_EQ(-ESPIPE, vfs_seek(fds[1], 5, VFS_SEEK_SET));


  KTEST_BEGIN("vfs_pipe(): vfs_getdents() on pipe fd");
  kdirent_t kdbuf;
  KEXPECT_EQ(-ENOTDIR, vfs_getdents(fds[0], &kdbuf, 10));
  KEXPECT_EQ(-ENOTDIR, vfs_getdents(fds[1], &kdbuf, 10));


  KTEST_BEGIN("vfs_pipe(): vfs_isatty() on pipe fd");
  KEXPECT_EQ(0, vfs_isatty(fds[0]));
  KEXPECT_EQ(0, vfs_isatty(fds[1]));

  KTEST_BEGIN("vfs_pipe(): test cleanup");
  KEXPECT_EQ(0, vfs_close(fds[0]));
  KEXPECT_EQ(0, vfs_close(fds[1]));

  KTEST_BEGIN("vfs_pipe(): too many files open");
  vfs_set_force_no_files(true);
  fds[0] = 100;
  fds[1] = 100;
  KEXPECT_EQ(-ENFILE, vfs_pipe(fds));
  vfs_set_force_no_files(false);

  KTEST_BEGIN("vfs_pipe(): too many FDs open");
  struct apos_rlimit lim;
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_NOFILE, &lim));
  const struct apos_rlimit orig_lim = lim;

  // Hit first fd.
  lim.rlim_cur = 0;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));
  KEXPECT_EQ(-EMFILE, vfs_pipe(fds));

  // Hit second fd.
  lim.rlim_cur = 1;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));
  KEXPECT_EQ(-EMFILE, vfs_pipe(fds));

  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &orig_lim));

  KTEST_BEGIN("vfs_pipe(): poll on pipe endpoints");
  KEXPECT_EQ(0, vfs_pipe(fds));
  struct apos_pollfd pfds[2];
  pfds[0].fd = fds[0];
  pfds[1].fd = fds[1];
  pfds[0].events = pfds[1].events = KPOLLIN | KPOLLOUT;
  KEXPECT_EQ(1, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(KPOLLOUT, pfds[1].revents);

  KEXPECT_EQ(3, vfs_write(fds[1], "abc", 3));
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(KPOLLIN, pfds[0].revents);
  KEXPECT_EQ(KPOLLOUT, pfds[1].revents);

  KEXPECT_EQ(0, vfs_close(fds[0]));
  KEXPECT_EQ(0, vfs_close(fds[1]));

  // TODO(aoates): other tests to write:
  //  - write or read from unconnected pipe
  //  - fchown, fchmod
}

static void umask_test_child(void* arg) {
  proc_exit(proc_umask(0));
}

static void umask_test(void) {
  KTEST_BEGIN("umask: default value");
  const kmode_t orig_umask = proc_umask(0);
  KEXPECT_EQ(022, orig_umask);
  proc_umask(orig_umask);

  KTEST_BEGIN("umask: tracks non-mode bits");
  proc_umask(VFS_S_IFIFO | VFS_S_IRWXU);
  KEXPECT_EQ(VFS_S_IFIFO | VFS_S_IRWXU, proc_umask(orig_umask));

  KTEST_BEGIN("umask: inherited on fork()");
  proc_umask(0123);
  kpid_t child = proc_fork(&umask_test_child, NULL);
  KEXPECT_GE(child, 0);
  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(0123, status);
  proc_umask(orig_umask);


  KTEST_BEGIN("umask: applied by open()");
  proc_umask(VFS_S_IFIFO | 0026);
  int fd = vfs_open("umask_test_file", VFS_O_CREAT | VFS_O_RDONLY,
                    VFS_S_IWUSR | VFS_S_IXUSR | VFS_S_IRWXG | VFS_S_IRWXO);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  apos_stat_t st;
  KEXPECT_EQ(0, vfs_stat("umask_test_file", &st));
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IWUSR | VFS_S_IXUSR | VFS_S_IRGRP |
             VFS_S_IXGRP | VFS_S_IXOTH, st.st_mode);
  KEXPECT_EQ(0, vfs_unlink("umask_test_file"));


  KTEST_BEGIN("umask: applied by mkdir()");
  proc_umask(VFS_S_IFIFO | 0026);
  KEXPECT_EQ(0, vfs_mkdir("umask_test_dir", VFS_S_IWUSR | VFS_S_IXUSR |
                                                VFS_S_IRWXG | VFS_S_IRWXO));
  kmemset(&st, 0, sizeof(apos_stat_t));
  KEXPECT_EQ(0, vfs_stat("umask_test_dir", &st));
  KEXPECT_EQ(VFS_S_IFDIR | VFS_S_IWUSR | VFS_S_IXUSR | VFS_S_IRGRP |
             VFS_S_IXGRP | VFS_S_IXOTH, st.st_mode);
  KEXPECT_EQ(0, vfs_rmdir("umask_test_dir"));


  KTEST_BEGIN("umask: applied by mknod()");
  proc_umask(VFS_S_IFIFO | 0026);
  KEXPECT_EQ(
      0, vfs_mknod("umask_test_node", VFS_S_IFCHR | VFS_S_IWUSR | VFS_S_IXUSR |
                                          VFS_S_IRWXG | VFS_S_IRWXO,
                   kmakedev(0, 0)));
  kmemset(&st, 0, sizeof(apos_stat_t));
  KEXPECT_EQ(0, vfs_stat("umask_test_node", &st));
  KEXPECT_EQ(VFS_S_IFCHR | VFS_S_IWUSR | VFS_S_IXUSR | VFS_S_IRGRP |
             VFS_S_IXGRP | VFS_S_IXOTH, st.st_mode);
  KEXPECT_EQ(0, vfs_unlink("umask_test_node"));

  proc_umask(orig_umask);
}

static ssize_t read_all(int fd, void* buf, size_t len) {
  kmemset(buf, 0xFF, len);
  size_t offset = 0;
  while (offset < len) {
    size_t chunk_size = len - offset;
    int read_bytes = vfs_read(fd, buf + offset, chunk_size);
    if (read_bytes < 0) return read_bytes;
    if (read_bytes == 0) break;
    offset += read_bytes;
  }

  return offset;
}

static bool is_all_char(const char* buf, char c, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (buf[i] != c) {
      KLOG("char %zu is %c, not %c\n", i, buf[i], c);
      return false;
    }
  }
  return true;
}

static void ftruncate_test(void) {
  const char kFile[] = "/trunc_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];
  const int kBigBufSize = 2500;
  char* big_buf = kmalloc(kBigBufSize);
  kmemset(buf, 0, kBufSize);
  create_file_with_data(kFile, "abcdefghijklmnopqrstuvwxyz");

  KTEST_BEGIN("vfs_seek(): extend by a lot");
  int fd = vfs_open(kFile, VFS_O_RDWR);
  const int kNumZeros = 563 * 4;
  KEXPECT_EQ(26 + kNumZeros, vfs_seek(fd, kNumZeros, VFS_SEEK_END));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(26, stat.st_size);

  KEXPECT_EQ(3, vfs_write(fd, "ABC", 3));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(26 + kNumZeros + 3, stat.st_size);

  vfs_close(fd);
  block_cache_clear_unpinned();

  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(26 + kNumZeros + 3, read_all(fd, big_buf, kBigBufSize));
  KEXPECT_EQ(0, kstrncmp(big_buf, "abcdefghijklmnopqrstuvwxyz", 26));
  KEXPECT_EQ(true, is_all_char(big_buf + 26, '\0', kNumZeros));
  KEXPECT_EQ('A', big_buf[26 + kNumZeros]);
  KEXPECT_EQ('B', big_buf[26 + kNumZeros + 1]);
  KEXPECT_EQ('C', big_buf[26 + kNumZeros + 2]);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): extend file (small)");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 16));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_CUR));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(16, stat.st_size);
  KEXPECT_EQ(16, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "0123456789\0\0\0\0\0\0", 16));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(19, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(19, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "0123456789\0\0\0\0\0\0abc", 19));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): truncate file (small)");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(3, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 6));
  KEXPECT_EQ(3, vfs_seek(fd, 0, VFS_SEEK_CUR));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(6, stat.st_size);
  kmemset(buf, 0xFF, kBufSize);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "012345", 6));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(9, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "012345abc", 9));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): extend file over old data");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 6));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 9));
  KEXPECT_EQ(9, vfs_seek(fd, 0, VFS_SEEK_END));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(12, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(12, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "012345\0\0\0abc", 12));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): extend file (even block size)");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  const int kFsBlockSize = 1024;
  kmemset(big_buf, 'A', kFsBlockSize);
  KEXPECT_EQ(kFsBlockSize, vfs_write(fd, big_buf, kFsBlockSize));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 2 * kFsBlockSize));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(2 * kFsBlockSize, read_all(fd, big_buf, kBigBufSize));
  KEXPECT_EQ(true, is_all_char(big_buf, 'A', kFsBlockSize));
  KEXPECT_EQ(true, is_all_char(big_buf + kFsBlockSize, '\0', kFsBlockSize));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): extend file over old data (large)");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 6));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, kNumZeros));
  KEXPECT_EQ(kNumZeros, vfs_seek(fd, 0, VFS_SEEK_END));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(kNumZeros + 3, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(kNumZeros + 3, read_all(fd, big_buf, kBigBufSize));
  KEXPECT_EQ(0, kstrncmp(big_buf, "012345", 6));
  KEXPECT_EQ(true, is_all_char(big_buf + 6, '\0', kNumZeros - 6));
  KEXPECT_EQ('a', big_buf[kNumZeros]);
  KEXPECT_EQ('b', big_buf[kNumZeros + 1]);
  KEXPECT_EQ('c', big_buf[kNumZeros + 2]);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): extend file (large)");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 10 + kNumZeros));
  vfs_close(fd);
  block_cache_clear_unpinned();

  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(10 + kNumZeros, stat.st_size);
  kmemset(big_buf, 0xFF, kBigBufSize);
  KEXPECT_EQ(10 + kNumZeros, read_all(fd, big_buf, kBigBufSize));
  KEXPECT_STREQ("0123456789", big_buf);
  KEXPECT_EQ(true, is_all_char(big_buf + 10, '\0', kNumZeros));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(10 + kNumZeros, vfs_seek(fd, -3, VFS_SEEK_CUR));
  kmemset(buf, '\0', kBufSize);
  KEXPECT_EQ(3, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(10 + kNumZeros + 3, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): truncate file (large)");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(10 + kNumZeros, vfs_seek(fd, 10 + kNumZeros, VFS_SEEK_SET));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 6));
  KEXPECT_EQ(10 + kNumZeros + 3, vfs_seek(fd, 0, VFS_SEEK_CUR));
  vfs_close(fd);
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(6, stat.st_size);
  kmemset(buf, 0xFF, kBufSize);
  KEXPECT_EQ(6, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "012345", 6));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): truncate then write past end");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(10, vfs_seek(fd, 0, VFS_SEEK_END));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 6));
  KEXPECT_EQ(0, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(3, vfs_write(fd, "abc", 3));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(13, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  kmemset(buf, 0xFF, kBufSize);
  KEXPECT_EQ(13, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kstrncmp(buf, "012345\0\0\0\0\0\0\0abc", 13));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): truncate to zero");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 0));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): truncate to same length");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 10));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(10, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): fd open O_WRONLY");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_WRONLY);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 2));
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(2, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_ftruncate(): bad offset");
  create_file_with_data(kFile, "0123456789");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(-EINVAL, vfs_ftruncate(fd, -1));
  // TODO(aoates): test setting a too-big size.
  vfs_close(fd);


  KTEST_BEGIN("vfs_ftruncate(): bad fd");
  KEXPECT_EQ(-EBADF, vfs_ftruncate(-1, 0));
  KEXPECT_EQ(-EBADF, vfs_ftruncate(10000, 0));
  fd = vfs_open(kFile, VFS_O_RDWR);
  vfs_close(fd);
  KEXPECT_EQ(-EBADF, vfs_ftruncate(fd, 0));


  KTEST_BEGIN("vfs_ftruncate(): fd not open for writing");
  fd = vfs_open(kFile, VFS_O_RDONLY);
  KEXPECT_EQ(-EBADF, vfs_ftruncate(fd, 0));
  KEXPECT_EQ(-EBADF, vfs_ftruncate(fd, 1000));
  KEXPECT_EQ(-EBADF, vfs_ftruncate(fd, 10));
  vfs_close(fd);


  if (TRUNCATE_MANY_LARGE_FILES_TEST) {
    // Allocate many large files that are truncated to small files to ensure the
    // filesystem cleans up properly when a file is truncated.
    KTEST_BEGIN("vfs_ftruncate(): many large -> small files");
    const int kNumFiles = 200;
    const int kLargeSize = kFsBlockSize * 200;
    KEXPECT_EQ(0, vfs_mkdir("trunc_large_files_test", VFS_S_IRWXU));
    for (int i = 0; i < kNumFiles; ++i) {
      ksprintf(buf, "trunc_large_files_test/f%d", i);
      fd = vfs_open(buf, VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
      KEXPECT_EQ(0, vfs_ftruncate(fd, kLargeSize));
      for (int blk = 0; blk < kLargeSize / kFsBlockSize; blk++) {
        vfs_seek(fd, blk * kFsBlockSize, VFS_SEEK_SET);
        vfs_write(fd, "abc", 3);
      }
      vfs_close(fd);
      fd = vfs_open(buf, VFS_O_RDWR);
      KEXPECT_EQ(0, vfs_ftruncate(fd, 0));
      vfs_close(fd);
    }
    for (int i = 0; i < kNumFiles; ++i) {
      ksprintf(buf, "trunc_large_files_test/f%d", i);
      KEXPECT_EQ(0, vfs_unlink(buf));
    }
    KEXPECT_EQ(0, vfs_rmdir("trunc_large_files_test"));
  }


  // TODO(aoates): test truncate on non-regular files.

  // Clean up.
  kfree(big_buf);
  vfs_unlink(kFile);
}

static void truncate_test(void) {
  const char kFile[] = "/trunc_test_file";
  apos_stat_t stat;

  KTEST_BEGIN("vfs_truncate(): basic test (truncate)");
  create_file_with_data(kFile, "abcdef");
  KEXPECT_EQ(0, vfs_truncate(kFile, 4));
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(4, stat.st_size);
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("vfs_truncate(): basic test (truncate to zero)");
  create_file_with_data(kFile, "abcdef");
  KEXPECT_EQ(0, vfs_truncate(kFile, 0));
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("vfs_truncate(): basic test (expand)");
  create_file_with_data(kFile, "abcdef");
  KEXPECT_EQ(0, vfs_truncate(kFile, 10));
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(10, stat.st_size);
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("vfs_truncate(): through symlink");
  create_file_with_data(kFile, "abcdef");
  KEXPECT_EQ(0, vfs_symlink(kFile, "trunc_link"));
  KEXPECT_EQ(0, vfs_truncate("trunc_link", 10));
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(10, stat.st_size);
  KEXPECT_EQ(0, vfs_unlink("trunc_link"));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("vfs_truncate(): directory");
  KEXPECT_EQ(0, vfs_mkdir("_trunc_dir", VFS_S_IRWXU));
  KEXPECT_EQ(-EISDIR, vfs_truncate("_trunc_dir", 3));
  KEXPECT_EQ(-EISDIR, vfs_truncate("_trunc_dir", 0));
  KEXPECT_EQ(0, vfs_rmdir("_trunc_dir"));

  KTEST_BEGIN("vfs_truncate(): non-existant file");
  KEXPECT_EQ(-ENOENT, vfs_truncate(kFile, 0));
  KEXPECT_EQ(-ENOENT, vfs_truncate(kFile, 5));

  KTEST_BEGIN("vfs_truncate(): invalid offset");
  create_file_with_data(kFile, "abcdef");
  KEXPECT_EQ(-EINVAL, vfs_truncate(kFile, -6));
  KEXPECT_EQ(-EINVAL, vfs_truncate(0x0, 5));
  // TODO(aoates): test EFBIG (setting file too large).
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(6, stat.st_size);
  KEXPECT_EQ(0, vfs_unlink(kFile));
}

static void open_truncate_test(void) {
  const char kFile[] = "/open_trunc_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];

  KTEST_BEGIN("vfs_open(): basic O_TRUNC");
  create_file_with_data(kFile, "abcdefghijklmnopqrstuvwxyz");
  int fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_TRUNC);
  KEXPECT_GE(fd, 0);

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_open(): O_TRUNC w/ O_WRONLY");
  create_file_with_data(kFile, "abcdefghijklmnopqrstuvwxyz");
  fd = vfs_open(kFile, VFS_O_WRONLY | VFS_O_TRUNC);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_open(): O_TRUNC on read-only file");
  create_file_with_data(kFile, "abcdefghijklmnopqrstuvwxyz");
  KEXPECT_EQ(0, vfs_chmod(kFile, VFS_S_IRUSR));
  fd = vfs_open(kFile, VFS_O_RDONLY | VFS_O_TRUNC);
  KEXPECT_EQ(-EACCES, fd);

  KEXPECT_EQ(0, vfs_lstat(kFile, &stat));
  KEXPECT_EQ(26, stat.st_size);
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_open(): O_TRUNC on directory");
  KEXPECT_EQ(0, vfs_mkdir("_trunc_test_dir", VFS_S_IRWXU));
  fd = vfs_open("_trunc_test_dir", VFS_O_RDWR | VFS_O_TRUNC);
  KEXPECT_EQ(-EISDIR, fd);
  KEXPECT_EQ(0, vfs_rmdir("_trunc_test_dir"));


  KTEST_BEGIN("vfs_open(): O_TRUNC on non-existant file");
  KEXPECT_EQ(-ENOENT, vfs_open(kFile, VFS_O_RDWR | VFS_O_TRUNC));
  KEXPECT_EQ(-ENOENT, vfs_lstat(kFile, &stat));


  KTEST_BEGIN("vfs_open(): O_TRUNC on newly created file");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_TRUNC | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_open(): O_TRUNC on already-empty file");
  create_file_with_data(kFile, "");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_TRUNC);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("vfs_truncate(): preserves uid, gid, and mode");
  create_file_with_data(kFile, "abc");
  KEXPECT_EQ(0, vfs_chown(kFile, 1, 2));
  KEXPECT_EQ(0, vfs_chmod(kFile, VFS_S_IWGRP));
  KEXPECT_EQ(0, vfs_truncate(kFile, 5));
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(5, stat.st_size);
  KEXPECT_EQ(1, stat.st_uid);
  KEXPECT_EQ(2, stat.st_gid);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IWGRP, stat.st_mode);

  KTEST_BEGIN("vfs_ftruncate(): preserves uid, gid, and mode");
  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 6));
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(6, stat.st_size);
  KEXPECT_EQ(1, stat.st_uid);
  KEXPECT_EQ(2, stat.st_gid);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IWGRP, stat.st_mode);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_open(): O_TRUNC preserves uid, gid, and mode");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_TRUNC);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_stat(kFile, &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(1, stat.st_uid);
  KEXPECT_EQ(2, stat.st_gid);
  KEXPECT_EQ(VFS_S_IFREG | VFS_S_IWGRP, stat.st_mode);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));
}

static void truncate_filetype_test(void) {
  KTEST_BEGIN("vfs_truncate(): directory test");
  KEXPECT_EQ(0, vfs_mkdir("_trunc_test_dir", VFS_S_IRWXU));
  KEXPECT_EQ(-EISDIR, vfs_truncate("_trunc_test_dir", 0));
  KEXPECT_EQ(-EISDIR, vfs_truncate("_trunc_test_dir", 5));

  KTEST_BEGIN("vfs_ftruncate(): directory test");
  int fd = vfs_open("_trunc_test_dir", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_NE(0, vfs_ftruncate(fd, 0));
  KEXPECT_NE(0, vfs_ftruncate(fd, 5));
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_open(): O_TRUNC directory test");
  KEXPECT_EQ(-EACCES, vfs_open("_trunc_test_dir", VFS_O_RDONLY | VFS_O_TRUNC));
  KEXPECT_EQ(-EISDIR, vfs_open("_trunc_test_dir", VFS_O_RDWR | VFS_O_TRUNC));
  KEXPECT_EQ(0, vfs_rmdir("_trunc_test_dir"));

  // Truncate tested on block dev in the block dev test above.

  KTEST_BEGIN("vfs_truncate(): on symlink");
  create_file_with_data("_trunc_target", "abc");
  KEXPECT_EQ(0, vfs_symlink("_trunc_target", "_trunc_link"));
  KEXPECT_EQ(0, vfs_truncate("_trunc_link", 1));
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("_trunc_target", &stat));
  KEXPECT_EQ(1, stat.st_size);

  KTEST_BEGIN("vfs_ftruncate(): on symlink");
  fd = vfs_open("_trunc_link", VFS_O_RDWR);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 5));
  KEXPECT_EQ(0, vfs_stat("_trunc_target", &stat));
  KEXPECT_EQ(5, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_open(): O_TRUNC on symlink");
  fd = vfs_open("_trunc_link", VFS_O_RDWR | VFS_O_TRUNC);
  KEXPECT_EQ(0, vfs_stat("_trunc_target", &stat));
  KEXPECT_EQ(0, stat.st_size);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink("_trunc_link"));
  KEXPECT_EQ(0, vfs_unlink("_trunc_target"));

  // Character device tested in TTY test.

  KTEST_BEGIN("vfs_ftruncate(): on pipe test");
  int pipe_fds[2];
  KEXPECT_EQ(0, vfs_pipe(pipe_fds));
  KEXPECT_EQ(3, vfs_write(pipe_fds[1], "abc", 3));
  KEXPECT_EQ(-EBADF, vfs_ftruncate(pipe_fds[0], 1));
  KEXPECT_EQ(0, vfs_ftruncate(pipe_fds[1], 1));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(pipe_fds[0], buf, 10));
  KEXPECT_EQ(0, vfs_close(pipe_fds[0]));
  KEXPECT_EQ(0, vfs_close(pipe_fds[1]));

  KTEST_BEGIN("vfs_truncate(): on FIFO test");
  KEXPECT_EQ(0, vfs_mknod("_trunc_fifo", VFS_S_IFIFO, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_truncate("_trunc_fifo", 5));
  // We don't test the contents b/c that would be a PITA; assuming the pipe test
  // above is sufficient.  Likewise we don't test vfs_open(VFS_O_TRUNC), since
  // that would be a pain.
  KEXPECT_EQ(0, vfs_unlink("_trunc_fifo"));
}

const int kMultiThreadAppendTestNumWrites = 100;
static void* append_multi_thread_worker(void* arg) {
  const char kFile[] = "/open_append_test_file";
  int fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_APPEND);
  KEXPECT_GE(fd, 0);
  for (int i = 0; i < kMultiThreadAppendTestNumWrites; ++i) {
    char buf[2] = {0, 0};
    buf[0] = (intptr_t)arg + '0';
    int result = vfs_write(fd, buf, 1);
    if (result != 1) {
      KEXPECT_EQ(result, 1);
      break;
    }
  }
  KEXPECT_EQ(0, vfs_close(fd));
  return NULL;
}

static void append_test(void) {
  const char kFile[] = "/open_append_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];
  const int kBigBufSize = 2500;
  char* big_buf = kmalloc(kBigBufSize);
  kmemset(buf, 0, kBufSize);

  KTEST_BEGIN("vfs_open(): basic O_APPEND");
  create_file_with_data(kFile, "abcdef");
  int fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_APPEND);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(3, vfs_write(fd, "123", 3));
  KEXPECT_EQ(9, vfs_seek(fd, 0, VFS_SEEK_CUR));

  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(2, vfs_write(fd, "45", 2));
  KEXPECT_EQ(11, vfs_seek(fd, 0, VFS_SEEK_CUR));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(11, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  kmemset(buf, '\0', kBufSize);
  KEXPECT_EQ(11, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("abcdef12345", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_open(): O_APPEND with dup()d fd");
  create_file_with_data(kFile, "abcdef");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_APPEND);
  KEXPECT_GE(fd, 0);
  int fd2 = vfs_dup(fd);

  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(3, vfs_write(fd, "123", 3));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(2, vfs_write(fd2, "45", 2));
  KEXPECT_EQ(11, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(11, vfs_seek(fd2, 0, VFS_SEEK_CUR));

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(11, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  kmemset(buf, '\0', kBufSize);
  KEXPECT_EQ(11, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("abcdef12345", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_close(fd2));
  KEXPECT_EQ(0, vfs_unlink(kFile));


  KTEST_BEGIN("vfs_open(): O_APPEND same file, independent fds");
  create_file_with_data(kFile, "abcdef");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_APPEND);
  fd2 = vfs_open(kFile, VFS_O_RDWR | VFS_O_APPEND);
  KEXPECT_GE(fd, 0);
  KEXPECT_GE(fd2, 0);

  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(3, vfs_write(fd, "123", 3));
  KEXPECT_EQ(9, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(0, vfs_seek(fd2, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(2, vfs_write(fd2, "45", 2));
  KEXPECT_EQ(9, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(11, vfs_seek(fd2, 0, VFS_SEEK_CUR));

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(11, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  kmemset(buf, '\0', kBufSize);
  KEXPECT_EQ(11, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("abcdef12345", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_close(fd2));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN(
      "vfs_open(): O_APPEND same file, independent fds (only one APPENDing)");
  create_file_with_data(kFile, "abcdef");
  fd = vfs_open(kFile, VFS_O_RDWR | VFS_O_APPEND);
  fd2 = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_GE(fd2, 0);

  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(3, vfs_write(fd, "123", 3));
  KEXPECT_EQ(9, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(0, vfs_seek(fd2, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(2, vfs_write(fd2, "45", 2));
  KEXPECT_EQ(9, vfs_seek(fd, 0, VFS_SEEK_CUR));
  KEXPECT_EQ(2, vfs_seek(fd2, 0, VFS_SEEK_CUR));

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(9, stat.st_size);
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  kmemset(buf, '\0', kBufSize);
  KEXPECT_EQ(9, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("45cdef123", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_close(fd2));
  KEXPECT_EQ(0, vfs_unlink(kFile));

  KTEST_BEGIN("vfs_open(): O_APPEND multi-thread atomicity test");
  create_file_with_data(kFile, "");
  const int kNumThreads = 3;
  kthread_t threads[kNumThreads];
  for (intptr_t i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[i], &append_multi_thread_worker,
                                     (void*)i));
  }
  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }
  fd = vfs_open(kFile, VFS_O_RDONLY);
  int result = read_all(fd, big_buf, kBigBufSize);
  KEXPECT_EQ(kNumThreads * kMultiThreadAppendTestNumWrites, result);
  int counters[kNumThreads];
  for (int i = 0; i < kNumThreads; ++i) counters[i] = 0;
  for (int i = 0; i < result; ++i) {
    if (big_buf[i] < '0' || big_buf[i] > '9')
      continue;
    counters[big_buf[i] - '0']++;
  }
  for (int i = 0; i < kNumThreads; ++i)
    KEXPECT_EQ(kMultiThreadAppendTestNumWrites, counters[i]);
  vfs_close(fd);
  vfs_unlink(kFile);

  kfree(big_buf);
}

const int kExclTestFiles = 10;

static void* excl_test_worker(void* arg) {
  int* counters = (int*)arg;
  for (int i = 0; i < kExclTestFiles; ++i) {
    char name[100];
    ksprintf(name, "_excl_test_%d", i);
    int fd = vfs_open(name, VFS_O_RDWR | VFS_O_CREAT | VFS_O_EXCL, VFS_S_IRWXU);
    if (fd >= 0) {
      counters[i]++;
      vfs_close(fd);
    }
  }
  return 0x0;
}

static void excl_test(void) {
  KTEST_BEGIN("vfs_open(): O_EXCL test");
  KEXPECT_EQ(-ENOENT, vfs_open("excl_path", VFS_O_RDWR | VFS_O_EXCL));
  int fd =
      vfs_open("excl_path", VFS_O_RDWR | VFS_O_CREAT | VFS_O_EXCL, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(-EEXIST,
             vfs_open("excl_path", VFS_O_RDWR | VFS_O_CREAT | VFS_O_EXCL,
                      VFS_S_IRWXU));
  fd = vfs_open("excl_path", VFS_O_RDWR | VFS_O_EXCL, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("vfs_open(): O_EXCL symlink test");
  KEXPECT_EQ(0, vfs_symlink("excl_path", "good_link"));
  KEXPECT_EQ(0, vfs_symlink("excl_path_2", "bad_link"));
  KEXPECT_EQ(0, vfs_symlink("good_link", "good_link2"));
  KEXPECT_EQ(-EEXIST,
             vfs_open("good_link", VFS_O_RDWR | VFS_O_CREAT | VFS_O_EXCL,
                      VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST,
             vfs_open("good_link2", VFS_O_RDWR | VFS_O_CREAT | VFS_O_EXCL,
                      VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST,
             vfs_open("bad_link", VFS_O_RDWR | VFS_O_CREAT | VFS_O_EXCL,
                      VFS_S_IRWXU));
  KEXPECT_EQ(-ENOENT, vfs_open("excl_path_2", VFS_O_RDWR));
  KEXPECT_EQ(0, vfs_unlink("bad_link"));
  KEXPECT_EQ(0, vfs_unlink("good_link"));
  KEXPECT_EQ(0, vfs_unlink("good_link2"));
  KEXPECT_EQ(0, vfs_unlink("excl_path"));

  KTEST_BEGIN("vfs_open(): O_EXCL multi-thread test");
  const int kExclTestThreads = 10;
  kthread_t threads[kExclTestThreads];
  int counters[kExclTestFiles];
  for (int i = 0; i < kExclTestFiles; ++i) counters[i] = 0;
  for (int i = 0; i < kExclTestThreads; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[i], &excl_test_worker, counters));
  }
  for (int i = 0; i < kExclTestThreads; ++i) kthread_join(threads[i]);
  for (int i = 0; i < kExclTestFiles; ++i) {
    KEXPECT_EQ(1, counters[i]);
    char name[100];
    ksprintf(name, "_excl_test_%d", i);
    KEXPECT_EQ(0, vfs_unlink(name));
  }
}

static void o_directory_test(void) {
  KTEST_BEGIN("vfs_open(): O_DIRECTORY on directory");
  KEXPECT_EQ(0, vfs_mkdir("_o_dir_dir", VFS_S_IRWXU));
  int fd = vfs_open("_o_dir_dir", VFS_O_RDONLY | VFS_O_DIRECTORY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_rmdir("_o_dir_dir"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on regular file");
  create_file_with_data("_o_dir_file", "");
  KEXPECT_EQ(-ENOTDIR, vfs_open("_o_dir_file", VFS_O_RDONLY | VFS_O_DIRECTORY));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_file"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on char dev");
  KEXPECT_EQ(0, vfs_mknod("_o_dir_chr", VFS_S_IFCHR, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_open("_o_dir_chr", VFS_O_RDONLY | VFS_O_DIRECTORY));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_chr"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on block dev");
  KEXPECT_EQ(0, vfs_mknod("_o_dir_blk", VFS_S_IFBLK, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_open("_o_dir_blk", VFS_O_RDONLY | VFS_O_DIRECTORY));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_blk"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on FIFO");
  KEXPECT_EQ(0, vfs_mknod("_o_dir_fifo", VFS_S_IFIFO, kmakedev(0, 0)));
  KEXPECT_EQ(-ENOTDIR, vfs_open("_o_dir_fifo", VFS_O_RDONLY | VFS_O_DIRECTORY));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_fifo"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on symlink to file");
  create_file_with_data("_o_dir_file", "");
  KEXPECT_EQ(0, vfs_symlink("_o_dir_file", "_o_dir_link"));
  KEXPECT_EQ(-ENOTDIR, vfs_open("_o_dir_link", VFS_O_RDONLY | VFS_O_DIRECTORY));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_link"));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_file"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on dangling symlink");
  KEXPECT_EQ(0, vfs_symlink("_o_dir_file", "_o_dir_link"));
  KEXPECT_EQ(-ENOENT, vfs_open("_o_dir_link", VFS_O_RDONLY | VFS_O_DIRECTORY));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_link"));

  KTEST_BEGIN("vfs_open(): O_DIRECTORY on symlink to directory");
  KEXPECT_EQ(0, vfs_mkdir("_o_dir_dir", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("_o_dir_dir", "_o_dir_link"));
  fd = vfs_open("_o_dir_link", VFS_O_RDONLY | VFS_O_DIRECTORY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_rmdir("_o_dir_dir"));
  KEXPECT_EQ(0, vfs_unlink("_o_dir_link"));
}

static void o_nofollow_test(void) {
  KTEST_BEGIN("vfs_open(): O_NOFOLLOW on regular file");
  create_file_with_data("_o_noflw_file", "");
  KEXPECT_EQ(0, vfs_mkdir("_o_noflw_dir", VFS_S_IRWXU));

  int fd = vfs_open("_o_noflw_file", VFS_O_RDONLY | VFS_O_NOFOLLOW);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("vfs_open(): O_NOFOLLOW on directory");
  fd = vfs_open("_o_noflw_dir", VFS_O_RDONLY | VFS_O_NOFOLLOW);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("vfs_open(): O_NOFOLLOW on symlink to file");
  KEXPECT_EQ(0, vfs_symlink("_o_noflw_file", "_o_noflw_link"));
  KEXPECT_EQ(-ELOOP, vfs_open("_o_noflw_link", VFS_O_RDONLY | VFS_O_NOFOLLOW));
  KEXPECT_EQ(0, vfs_unlink("_o_noflw_link"));


  KTEST_BEGIN("vfs_open(): O_NOFOLLOW on dangling symlink");
  KEXPECT_EQ(0, vfs_symlink("_o_noflw_file", "_o_noflw_link"));
  KEXPECT_EQ(-ELOOP, vfs_open("_o_noflw_link", VFS_O_RDONLY | VFS_O_NOFOLLOW));
  KEXPECT_EQ(0, vfs_unlink("_o_noflw_link"));


  KTEST_BEGIN("vfs_open(): O_NOFOLLOW on symlink to directory");
  KEXPECT_EQ(0, vfs_symlink("_o_noflw_dir", "_o_noflw_link"));
  KEXPECT_EQ(-ELOOP, vfs_open("_o_noflw_link", VFS_O_RDONLY | VFS_O_NOFOLLOW));
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_unlink("_o_noflw_link"));

  KEXPECT_EQ(0, vfs_rmdir("_o_noflw_dir"));
  KEXPECT_EQ(0, vfs_unlink("_o_noflw_file"));
}

static void o_cloexec_test_proc(void* arg) {
  char* argv[] = {"sleep", "10", NULL};
  char* envp[] = {NULL};
  do_execve("/bin/sleep", argv, envp, NULL, NULL);
  KEXPECT_EQ(1, 2);  // Should never get here.
}

static void o_cloexec_test(void) NO_THREAD_SAFETY_ANALYSIS {
  KTEST_BEGIN("vfs_open(): O_CLOEXEC on regular file");
  create_file_with_data("_o_cloexec_file", "");

  int fd1 = vfs_open("_o_cloexec_file", VFS_O_RDONLY);
  KEXPECT_GE(fd1, 0);
  KEXPECT_EQ(0, proc_current()->fds[fd1].flags);
  int fd2 = vfs_open("_o_cloexec_file", VFS_O_RDONLY | VFS_O_CLOEXEC);
  KEXPECT_GE(fd2, 0);
  KEXPECT_EQ(VFS_O_CLOEXEC, proc_current()->fds[fd2].flags);

#if ARCH_RUN_USER_TESTS
  kpid_t child = proc_fork(&o_cloexec_test_proc, NULL);
  while (!proc_get(child)->execed) {
    ksleep(50);
  }
  process_t* childp = proc_get(child);
  KEXPECT_NE(NULL, childp);
  KEXPECT_NE(PROC_UNUSED_FD, childp->fds[fd1].file);
  KEXPECT_EQ(PROC_UNUSED_FD, childp->fds[fd2].file);
  proc_kill(child, SIGKILL);
  KEXPECT_EQ(child, proc_wait(NULL));
#endif

  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(0, vfs_close(fd2));

  KEXPECT_EQ(0, vfs_unlink("_o_cloexec_file"));
}

static void link_test(void) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_link(): basic file test (link to same directory)");
  KEXPECT_EQ(0, vfs_mkdir("_link_test", VFS_S_IRWXU));
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_link("_link_test/file", "_link_test/fileB"));
  KEXPECT_EQ(0, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/fileB", &statB));

  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(statA.st_mode, statB.st_mode);
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/fileB", &statB));
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_link_test/fileB"));


  KTEST_BEGIN("vfs_link(): basic file test (link to different directory)");
  KEXPECT_EQ(0, vfs_mkdir("_link_test2", VFS_S_IRWXU));
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_link("_link_test/file", "_link_test2/fileB"));
  KEXPECT_EQ(0, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test2/fileB", &statB));

  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(statA.st_mode, statB.st_mode);
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test2/fileB", &statB));
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_link_test2/fileB"));


  KTEST_BEGIN("vfs_link(): can't link directory");
  KEXPECT_EQ(-EPERM, vfs_link("_link_test", "_link_test3"));
  KEXPECT_EQ(-EPERM, vfs_link("_link_test", "_link_test2/abc"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_link_test3", &statA));
  KEXPECT_EQ(-ENOENT, vfs_stat("_link_test2/abc", &statA));
}

static void link_testB(void) {
  apos_stat_t statA, statB, statC;

  KTEST_BEGIN("vfs_link(): can't link over existing file (same directory)");
  create_file_with_data("_link_test/file", "abc");
  create_file_with_data("_link_test/fileB", "abc");
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test/fileB"));
  KEXPECT_EQ(0, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/fileB", &statB));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(1, statB.st_nlink);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/fileB"));


  KTEST_BEGIN("vfs_link(): can't link over directory");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_link_test/dir", VFS_S_IRWXU));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test/dir"));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test"));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test2"));
  KEXPECT_EQ(0, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/dir", &statB));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_rmdir("_link_test/dir"));


  KTEST_BEGIN("vfs_link(): can't link file to self");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test/file"));
  KEXPECT_EQ(0, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));


  KTEST_BEGIN(
      "vfs_link(): can't link over existing file (different directory)");
  create_file_with_data("_link_test/file", "abc");
  create_file_with_data("_link_test2/fileB", "abc");
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test2/fileB"));
  KEXPECT_EQ(0, vfs_stat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test2/fileB", &statB));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(1, statB.st_nlink);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test2/fileB"));


  KTEST_BEGIN("vfs_link(): source is a symlink");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_symlink("file", "_link_test/symlink"));
  KEXPECT_EQ(0, vfs_link("_link_test/symlink", "_link_test/symlink2"));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink", &statB));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink2", &statC));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(2, statC.st_nlink);
  KEXPECT_EQ(VFS_S_IFLNK, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statC.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink2"));


  KTEST_BEGIN("vfs_link(): source is a broken symlink");
  KEXPECT_EQ(0, vfs_symlink("file", "_link_test/symlink"));
  KEXPECT_EQ(0, vfs_link("_link_test/symlink", "_link_test/symlink2"));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink", &statB));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink2", &statC));

  KEXPECT_EQ(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(2, statC.st_nlink);
  KEXPECT_EQ(VFS_S_IFLNK, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statC.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink2"));


  KTEST_BEGIN("vfs_link(): target is a symlink");
  create_file_with_data("_link_test/file", "abc");
  create_file_with_data("_link_test/file2", "abc");
  KEXPECT_EQ(0, vfs_symlink("file2", "_link_test/symlink"));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test/symlink"));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink", &statB));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file2", &statC));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(1, statC.st_nlink);
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFREG, statC.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/file2"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink"));


  KTEST_BEGIN("vfs_link(): target is a broken symlink");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_symlink("file2", "_link_test/symlink"));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test/symlink"));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink", &statB));
  KEXPECT_EQ(-ENOENT, vfs_lstat("_link_test/file2", &statB));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statB.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink"));


  KTEST_BEGIN("vfs_link(): target is a symlink");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_symlink("file", "_link_test/symlink"));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/file", "_link_test/symlink"));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink", &statB));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statB.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink"));


  KTEST_BEGIN("vfs_link(): source and target are symlinks");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(0, vfs_symlink("file", "_link_test/symlink"));
  KEXPECT_EQ(0, vfs_symlink("file", "_link_test/symlink2"));
  KEXPECT_EQ(-EEXIST, vfs_link("_link_test/symlink", "_link_test/symlink2"));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink", &statB));
  KEXPECT_EQ(0, vfs_lstat("_link_test/symlink2", &statC));

  KEXPECT_NE(statA.st_ino, statB.st_ino);
  KEXPECT_NE(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(1, statC.st_nlink);
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(VFS_S_IFLNK, statC.st_mode & VFS_S_IFMT);

  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/symlink2"));


  KTEST_BEGIN("vfs_link(): source is empty string");
  KEXPECT_EQ(-ENOENT, vfs_link("", "_link_test/symlink"));
  KEXPECT_EQ(-ENOENT, vfs_lstat("_link_test/symlink", &statA));


  KTEST_BEGIN("vfs_link(): target is empty string");
  create_file_with_data("_link_test/file", "abc");
  KEXPECT_EQ(-ENOENT, vfs_link("_link_test/file", ""));
  KEXPECT_EQ(0, vfs_lstat("_link_test/file", &statA));
  KEXPECT_EQ(0, vfs_unlink("_link_test/file"));


  KTEST_BEGIN("vfs_link(): source is character device");
  KEXPECT_EQ(0, vfs_mknod("_link_test/char_dev", VFS_S_IRWXU | VFS_S_IFCHR,
                          kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_link("_link_test/char_dev", "_link_test/cd_link"));
  KEXPECT_EQ(0, vfs_stat("_link_test/char_dev", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/cd_link", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_link_test/char_dev"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/cd_link"));


  KTEST_BEGIN("vfs_link(): source is block device");
  KEXPECT_EQ(0, vfs_mknod("_link_test/block_dev", VFS_S_IRWXU | VFS_S_IFBLK,
                          kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_link("_link_test/block_dev", "_link_test/bd_link"));
  KEXPECT_EQ(0, vfs_stat("_link_test/block_dev", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/bd_link", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_link_test/block_dev"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/bd_link"));


  KTEST_BEGIN("vfs_link(): source is FIFO");
  KEXPECT_EQ(0, vfs_mknod("_link_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU,
                          kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_link("_link_test/fifo", "_link_test/fifo_link"));
  KEXPECT_EQ(0, vfs_stat("_link_test/fifo", &statA));
  KEXPECT_EQ(0, vfs_stat("_link_test/fifo_link", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_link_test/fifo"));
  KEXPECT_EQ(0, vfs_unlink("_link_test/fifo_link"));


  KEXPECT_EQ(0, vfs_rmdir("_link_test"));
  KEXPECT_EQ(0, vfs_rmdir("_link_test2"));
}

typedef struct {
  int parent_ino;
  int dirA_ino;
  int dirB_ino;
} rename_test_state_t;

static void rename_testA(rename_test_state_t* s) {
  KTEST_BEGIN("vfs_rename(): basic file rename (same directory)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test", VFS_S_IRWXU));
  create_file_with_data("_rename_test/A", "abc");
  apos_stat_t statA, statB;
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statA.st_size);
  KEXPECT_EQ(1, statA.st_nlink);

  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): basic file rename (different directory)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statA));
  s->parent_ino = statA.st_ino;
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statA));
  s->dirA_ino = statA.st_ino;
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statA));
  s->dirB_ino = statA.st_ino;

  create_file_with_data("_rename_test/dirA/A", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statA.st_size);

  KEXPECT_EQ(0, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirB/B"));
}

static void rename_testB(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): basic file rename (move to sub-directory)");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statA.st_size);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirB/B"));


  KTEST_BEGIN("vfs_rename(): basic file rename (move to parent directory)");
  create_file_with_data("_rename_test/dirA/A", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/dirA/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statA.st_size);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): basic directory rename (same directory)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A/..", &statA));
  int orig_dotdot_ino  = statA.st_ino;
  KEXPECT_EQ(5, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B/.", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B/..", &statB));
  KEXPECT_EQ(orig_dotdot_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(5, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(4, statB.st_nlink);
}

static void rename_testC(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): basic directory rename (different directory)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A/..", &statA));
  const int orig_dotdot_ino  = statA.st_ino;
  KEXPECT_EQ(s->dirA_ino, statA.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/.", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/..", &statB));
  KEXPECT_NE(orig_dotdot_ino, statB.st_ino);
  KEXPECT_EQ(s->dirB_ino, statB.st_ino);
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B"));

  KTEST_BEGIN("vfs_rename(): file rename (over existing file; same directory)");
  create_file_with_data("_rename_test/A", "abc");
  create_file_with_data("_rename_test/B", "de");
  KEXPECT_EQ(0, vfs_link("_rename_test/B", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  int orig_A_ino = statA.st_ino;
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(3, statA.st_size);;
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  int orig_B_ino = statB.st_ino;
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(2, statB.st_size);

  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(orig_A_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/C", &statB));
  KEXPECT_EQ(2, statB.st_size);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(4, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/C"));


  KTEST_BEGIN("vfs_rename(): file rename (over file; different directory)");
  create_file_with_data("_rename_test/dirA/A", "abc");
  create_file_with_data("_rename_test/dirB/B", "de");
  KEXPECT_EQ(0, vfs_link("_rename_test/dirB/B", "_rename_test/dirA/C"));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(VFS_S_IFREG, statA.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statA.st_size);
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  orig_B_ino = statB.st_ino;
  KEXPECT_EQ(2, statB.st_nlink);

  KEXPECT_EQ(0, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/C", &statB));
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirB/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirA/C"));


  KTEST_BEGIN("vfs_rename(): dir rename (over existing dir; same directory)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/A/..", &statB));
  KEXPECT_EQ(6, statB.st_nlink);
  KEXPECT_EQ(s->parent_ino, statB.st_ino);

  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(5, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): dir rename (over dir; different directory)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(3, statB.st_nlink);

  KEXPECT_EQ(0, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/..", &statB));
  KEXPECT_EQ(s->dirB_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B"));
}

static void rename_testD(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): dir rename (over non-empty dir; same parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B/X", VFS_S_IRWXU));
  create_file_with_data("_rename_test/B/Y", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/A/..", &statB));
  KEXPECT_EQ(6, statB.st_nlink);
  KEXPECT_EQ(s->parent_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  int orig_B_ino = statB.st_ino;

  KEXPECT_EQ(-ENOTEMPTY, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B/X"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B/X", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B/Y"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rename("_rename_test/A", "_rename_test/B"));

  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/A/..", &statB));
  KEXPECT_EQ(s->parent_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B/..", &statB));
  KEXPECT_EQ(s->parent_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(6, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B/X"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A"));


  KTEST_BEGIN(
      "vfs_rename(): dir rename (over non-empty dir; different parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB/B/X", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  orig_B_ino = statB.st_ino;

  KEXPECT_EQ(-ENOTEMPTY,
             vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A/..", &statB));
  KEXPECT_EQ(s->dirA_ino, statB.st_ino);
  KEXPECT_EQ(3, statB.st_nlink);

  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/X", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/X/..", &statB));
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/..", &statB));
  KEXPECT_EQ(s->dirB_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B/X"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirA/A"));
}

static void rename_testE(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): non-empty dir rename");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA/A/X", VFS_S_IRWXU));
  create_file_with_data("_rename_test/dirA/A/Y", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(3, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A/X", &statB));
  int orig_X_ino = statB.st_ino;

  KEXPECT_EQ(0, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/X", &statB));
  KEXPECT_EQ(orig_X_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B/Y", &statB));
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(1, statB.st_nlink);

  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B/X"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirB/B/Y"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B"));


  KTEST_BEGIN("vfs_rename(): file rename over dir fails (same parent)");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  int orig_B_ino = statB.st_ino;

  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B/..", &statB));
  KEXPECT_EQ(s->parent_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(5, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));
}

static void rename_testF(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): file rename over dir fails (different parent)");
  create_file_with_data("_rename_test/dirA/A", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(1, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  int orig_B_ino = statB.st_ino;

  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(3, statB.st_size);

  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFDIR, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);

  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirA/A"));


  KTEST_BEGIN("vfs_rename(): dir rename over file fails (same parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  create_file_with_data("_rename_test/B", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(1, statB.st_nlink);
  orig_B_ino = statB.st_ino;

  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/A/..", &statB));
  KEXPECT_EQ(s->parent_ino, statB.st_ino);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(5, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));
}

static void rename_testG(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): dir rename over file fails (different parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirA/A", VFS_S_IRWXU));
  create_file_with_data("_rename_test/dirB/B", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(1, statB.st_nlink);
  int orig_B_ino = statB.st_ino;

  KEXPECT_EQ(-ENOTDIR,
             vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/B", &statB));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirB/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);

  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(VFS_S_IFREG, statB.st_mode & VFS_S_IFMT);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(3, statB.st_size);

  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirA/A"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirB/B"));


  KTEST_BEGIN("vfs_rename(): special file rename over dir fails (same parent)");
  KEXPECT_EQ(0, vfs_mknod("_rename_test/chr", VFS_S_IFCHR, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_mknod("_rename_test/blk", VFS_S_IFBLK, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_mknod("_rename_test/fifo", VFS_S_IFIFO, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));

  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/chr", "_rename_test/B"));
  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/blk", "_rename_test/B"));
  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/fifo", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_stat("_rename_test/chr", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/blk", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/fifo", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/chr"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/blk"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): dir rename over special file fails (same parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("_rename_test/chr", VFS_S_IFCHR, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_mknod("_rename_test/blk", VFS_S_IFBLK, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_mknod("_rename_test/fifo", VFS_S_IFIFO, kmakedev(0, 0)));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statA));
  KEXPECT_EQ(2, statA.st_nlink);

  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A", "_rename_test/chr"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A", "_rename_test/blk"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A", "_rename_test/fifo"));
  KEXPECT_EQ(0, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/chr", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/blk", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/fifo", &statB));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/chr"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/blk"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/fifo"));
}

static void rename_testH(rename_test_state_t* s) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): both src and dst don't exist (same parent)");
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(4, statB.st_nlink);


  KTEST_BEGIN("vfs_rename(): both src and dst don't exist (different parent)");
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(2, statB.st_nlink);


  KTEST_BEGIN("vfs_rename(): src doesn't exist, dst is file (same parent)");
  create_file_with_data("_rename_test/B", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statA));
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(4, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));


  KTEST_BEGIN(
      "vfs_rename(): src doesn't exist, dst is file (different parent)");
  create_file_with_data("_rename_test/dirB/B", "abc");
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statA));
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(3, statB.st_size);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/dirB/B"));


  KTEST_BEGIN("vfs_rename(): src doesn't exist, dst is dir (same parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statA));
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/B", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test", &statB));
  KEXPECT_EQ(5, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): src doesn't exist, dst is dir (different parent)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/dirB/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statA));
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/dirA/A", "_rename_test/dirB/B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("_rename_test/dirA/A", &statB));
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB/B", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirA", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_stat("_rename_test/dirB", &statB));
  KEXPECT_EQ(3, statB.st_nlink);
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB/B"));

  KTEST_BEGIN("vfs_rename(): rename root directory");
  // None should be possible.
  KEXPECT_NE(0, vfs_rename("/", "/A"));
  KEXPECT_NE(0, vfs_rename("/", "/"));
  KEXPECT_NE(0, vfs_rename("/", "/."));
  KEXPECT_NE(0, vfs_rename("_rename_test/dirB", "/"));
  KEXPECT_NE(0, vfs_rename("_rename_test/dirB", "/."));
}

static void rename_testI(void) {
  apos_stat_t statA, statB;

  KTEST_BEGIN("vfs_rename(): src and dst are the same (same parent)");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("A", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_symlink("_rename_test/X", "_rename_test/D"));
  create_file_with_data("_rename_test/E1", "abc");
  KEXPECT_EQ(0, vfs_link("_rename_test/E1", "_rename_test/E2"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statA));
  KEXPECT_EQ(1, statA.st_nlink);

  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/A"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/../_rename_test/A", "_rename_test/A"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/B", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/B", "_rename_test/B/../B"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/C", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/D", "_rename_test/D"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/E1", "_rename_test/E1"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/E1", "_rename_test/E2"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/E2", "_rename_test/E2"));
  KEXPECT_EQ(-ERENAMESAMEVNODE,
             vfs_rename_unique("_rename_test/E1", "_rename_test/E1"));
  KEXPECT_EQ(-ERENAMESAMEVNODE,
             vfs_rename_unique("_rename_test/E1", "_rename_test/E2"));
  KEXPECT_EQ(-ERENAMESAMEVNODE,
             vfs_rename_unique("_rename_test/E2", "_rename_test/E2"));

  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statB));
  KEXPECT_EQ(statA.st_ino, statB.st_ino);
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_lstat("_rename_test/B", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(0, vfs_lstat("_rename_test/C", &statB));
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_lstat("_rename_test/D", &statB));
  KEXPECT_EQ(1, statB.st_nlink);
  KEXPECT_EQ(0, vfs_lstat("_rename_test/E1", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  int orig_B_ino = statB.st_ino;
  KEXPECT_EQ(0, vfs_lstat("_rename_test/E2", &statB));
  KEXPECT_EQ(2, statB.st_nlink);
  KEXPECT_EQ(orig_B_ino, statB.st_ino);

  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/C"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/D"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/E1"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/E2"));


  KTEST_BEGIN("vfs_rename(): source path is bad");
  create_file_with_data("_rename_test/X", "abc");
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/A/X", "_rename_test/B"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/X/A", "_rename_test/B"));

  KTEST_BEGIN("vfs_rename(): destination path is bad");
  create_file_with_data("_rename_test/Y", "abc");
  KEXPECT_EQ(-ENOENT, vfs_rename("_rename_test/X", "_rename_test/A/X"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/X", "_rename_test/X/A"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/Y", "_rename_test/X/A"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/X"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/Y"));


  KTEST_BEGIN("vfs_rename(): reject paths ending in '.' or '..'");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/B/.", "_rename_test/C"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/B/..", "_rename_test/C"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A", "_rename_test/B/."));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A", "_rename_test/B/.."));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/B", "_rename_test/B/."));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/B", "_rename_test/B/.."));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): reject non-dir paths ending in '/'");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  create_file_with_data("_rename_test/F", "abc");
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A/", "_rename_test/C"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A", "_rename_test/C/"));
  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/A", "_rename_test/B/"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/A", "_rename_test/F/"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/B", "_rename_test/F/"));
  KEXPECT_EQ(-ENOTDIR, vfs_rename("_rename_test/B/", "_rename_test/F/"));

  KTEST_BEGIN("vfs_rename(): allow dir paths ending in '/'");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/Z", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_rename("_rename_test/B/", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/C", "_rename_test/D/"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/D/", "_rename_test/E/"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/E//", "_rename_test/G//"));
  KEXPECT_EQ(0, vfs_rename("_rename_test/G", "_rename_test/Z/"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/F"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/Z"));
}

static void rename_testJ(void) {
  KTEST_BEGIN("vfs_rename(): src is ancestor of dst");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A/B/C", VFS_S_IRWXU));
  create_file_with_data("_rename_test/A/B/C/F", "abc");
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A", "_rename_test/A/x"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A", "_rename_test/A/B"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A", "_rename_test/A/B/x"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A", "_rename_test/A/B/C/x"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test", "_rename_test/A/B/C/x"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test", "_rename_test/A/B/C"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A/B", "_rename_test/A/B/C/x"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A/B", "_rename_test/A/B/C/x/"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A/B", "_rename_test/A/B/C"));
  KEXPECT_EQ(-EINVAL, vfs_rename("_rename_test/A/B", "_rename_test/A/B/C/"));
  KEXPECT_NE(0, vfs_rename("_rename_test/A/B", "_rename_test/A/B/C/F"));
  char cwd[VFS_MAX_PATH_LENGTH];
  KEXPECT_LT(0, vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH));
  KEXPECT_EQ(0, vfs_chdir("_rename_test/A/B"));
  kstrcat(cwd, "/_rename_test/A");
  KEXPECT_EQ(-EINVAL, vfs_rename(cwd, "x"));
  KEXPECT_EQ(-EINVAL, vfs_rename(cwd, "C/x"));
  KEXPECT_EQ(0, vfs_chdir("../../.."));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A/B/C/F"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A/B/C"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A/B"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A"));


  KTEST_BEGIN("vfs_rename(): rename open file");
  create_file_with_data("_rename_test/A", "abc");
  char buf[100];
  kmemset(buf, '\0', 100);
  int fd = vfs_open("_rename_test/A", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(1, vfs_read(fd, buf, 1));
  KEXPECT_STREQ("a", buf);
  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(2, vfs_read(fd, buf, 100));
  KEXPECT_STREQ("bc", buf);
  KEXPECT_EQ(3, vfs_write(fd, "def", 3));
  KEXPECT_EQ(0, vfs_close(fd));
  fd = vfs_open("_rename_test/B", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(6, vfs_read(fd, buf, 100));
  KEXPECT_STREQ("abcdef", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));


  KTEST_BEGIN("vfs_rename(): rename over open file");
  create_file_with_data("_rename_test/A", "abc");
  create_file_with_data("_rename_test/B", "defg");
  kmemset(buf, '\0', 100);
  fd = vfs_open("_rename_test/B", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(2, vfs_read(fd, buf, 2));
  KEXPECT_STREQ("de", buf);
  KEXPECT_EQ(0, vfs_rename("_rename_test/A", "_rename_test/B"));
  KEXPECT_EQ(2, vfs_read(fd, buf, 100));
  KEXPECT_STREQ("fg", buf);
  KEXPECT_EQ(3, vfs_write(fd, "hij", 3));
  int fd2 = vfs_open("_rename_test/B", VFS_O_RDWR);
  KEXPECT_EQ(3, vfs_read(fd2, buf, 100));
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_close(fd2));

  fd = vfs_open("_rename_test/B", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  kmemset(buf, '\0', 100);
  KEXPECT_EQ(3, vfs_read(fd, buf, 100));
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));
}

static void rename_testK(void) {
  apos_stat_t statA;
  char cwd[VFS_MAX_PATH_LENGTH];

  KTEST_BEGIN("vfs_rename(): src is absolute path, dst is relative");
  KEXPECT_EQ(0, vfs_chdir("_rename_test"));
  create_file_with_data("A", "");
  KEXPECT_LT(0, vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH));
  kstrcat(cwd, "/A");
  KEXPECT_EQ(0, vfs_rename(cwd, "B"));
  KEXPECT_EQ(-ENOENT, vfs_stat("A", &statA));
  KEXPECT_EQ(0, vfs_stat("B", &statA));
  KEXPECT_EQ(0, vfs_unlink("B"));
  KEXPECT_EQ(0, vfs_chdir(".."));


  KTEST_BEGIN("vfs_rename(): src is relative path, dst is absolute");
  KEXPECT_EQ(0, vfs_chdir("_rename_test"));
  create_file_with_data("A", "");
  KEXPECT_LT(0, vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH));
  kstrcat(cwd, "/B");
  KEXPECT_EQ(0, vfs_rename("A", cwd));
  KEXPECT_EQ(-ENOENT, vfs_stat("A", &statA));
  KEXPECT_EQ(0, vfs_stat("B", &statA));
  KEXPECT_EQ(0, vfs_unlink("B"));
  KEXPECT_EQ(0, vfs_chdir(".."));


  KTEST_BEGIN("vfs_rename(): src and dst are absolute paths");
  KEXPECT_EQ(0, vfs_chdir("_rename_test"));
  create_file_with_data("A", "");
  KEXPECT_LT(0, vfs_getcwd(cwd, VFS_MAX_PATH_LENGTH));
  char cwd2[VFS_MAX_PATH_LENGTH];
  kstrcpy(cwd2, cwd);
  kstrcat(cwd, "/A");
  kstrcat(cwd2, "/B");
  KEXPECT_EQ(0, vfs_rename(cwd, cwd2));
  KEXPECT_EQ(-ENOENT, vfs_stat("A", &statA));
  KEXPECT_EQ(0, vfs_stat("B", &statA));
  KEXPECT_EQ(0, vfs_unlink("B"));
  KEXPECT_EQ(0, vfs_chdir(".."));
}

static void rename_symlink_test(void) {
  apos_stat_t statA, statB, statC;
  char path[VFS_MAX_PATH_LENGTH];

  KTEST_BEGIN("vfs_rename(): rename symlink (target doesn't exist)");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statA));
  KEXPECT_EQ(0, vfs_symlink("A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/B", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statC));
  KEXPECT_EQ(statA.st_ino, statC.st_ino);
  KEXPECT_EQ(3, statC.st_size);
  KEXPECT_EQ(-ENOENT, vfs_lstat("_rename_test/B", &statC));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/C", &statC));
  KEXPECT_EQ(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(1, vfs_readlink("_rename_test/C", path, VFS_MAX_PATH_LENGTH));
  path[1] = '\0';
  KEXPECT_STREQ("A", path);
  KEXPECT_EQ(0, vfs_unlink("_rename_test/C"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));


  KTEST_BEGIN("vfs_rename(): broken rename symlink (target doesn't exist)");
  KEXPECT_EQ(0, vfs_symlink("bad", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/B", "_rename_test/C"));
  KEXPECT_EQ(-ENOENT, vfs_lstat("_rename_test/B", &statC));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/C", &statC));
  KEXPECT_EQ(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(3, vfs_readlink("_rename_test/C", path, VFS_MAX_PATH_LENGTH));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/C"));


  KTEST_BEGIN("vfs_rename(): rename symlink (target is file)");
  create_file_with_data("_rename_test/A", "abc");
  create_file_with_data("_rename_test/C", "x");
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statA));
  KEXPECT_EQ(0, vfs_symlink("A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/B", &statB));

  KEXPECT_EQ(0, vfs_rename("_rename_test/B", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statC));
  KEXPECT_EQ(statA.st_ino, statC.st_ino);
  KEXPECT_EQ(3, statC.st_size);
  KEXPECT_EQ(-ENOENT, vfs_lstat("_rename_test/B", &statC));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/C", &statC));
  KEXPECT_EQ(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(1, vfs_readlink("_rename_test/C", path, VFS_MAX_PATH_LENGTH));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/C"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));


  KTEST_BEGIN("vfs_rename(): rename symlink (target is dir)");
  create_file_with_data("_rename_test/A", "abc");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/C", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statA));
  KEXPECT_EQ(0, vfs_symlink("A", "_rename_test/B"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/B", &statB));

  KEXPECT_EQ(-EISDIR, vfs_rename("_rename_test/B", "_rename_test/C"));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/A", &statC));
  KEXPECT_EQ(0, vfs_lstat("_rename_test/B", &statC));
  KEXPECT_EQ(statB.st_ino, statC.st_ino);
  KEXPECT_EQ(0, vfs_lstat("_rename_test/C", &statC));
  KEXPECT_EQ(1, vfs_readlink("_rename_test/B", path, VFS_MAX_PATH_LENGTH));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/C"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/A"));

  // Other symlink tests,
  //  - symlink to file -> file (target exists, is symlink to {file, dir,
  //  broken})
  //  - src and dst both symlinks to same file (same dirent)
  //  - src and dst both symlinks to same file (different dirents, hard links)
  //  - src and dst both symlinks to same dir
}

const int RENAME_THREAD_ITERS = 100 * THREAD_SAFETY_MULTIPLIER;
static void* rename_symlink_func(void* arg) {
  int result = 0, i;
  for (i = 0; i < RENAME_THREAD_ITERS; ++i) {
    result = vfs_symlink("A", "_rename_test/templink");
    if (result) break;
    result = vfs_rename("_rename_test/templink", "_rename_test/link");
    if (result) break;
    result = vfs_symlink("B", "_rename_test/templink");
    if (result) break;
    result = vfs_rename("_rename_test/templink", "_rename_test/link");
    if (result) break;
    scheduler_yield();
  }
  KEXPECT_EQ(0, result);
  KEXPECT_EQ(RENAME_THREAD_ITERS, i);
  return NULL;
}

static void* rename_symlink_open_func(void* arg) {
  int result = 0, i;
  for (i = 0; i < RENAME_THREAD_ITERS * 2; ++i) {
    result = vfs_open("_rename_test/link/C", VFS_O_RDONLY);
    if (result < 0) break;
    vfs_close(result);
    scheduler_yield();
  }
  KEXPECT_EQ(0, result);
  KEXPECT_EQ(RENAME_THREAD_ITERS * 2, i);
  return NULL;
}

const int LOCK_ORDER_THREAD_ITERS = 20 * THREAD_SAFETY_MULTIPLIER;
static void* lock_order_func(void* arg) {
  const int id = (intptr_t)arg;
  int result = 0, i;

  char pathA[50], pathB[50], pathC[50];
  ksprintf(pathA, "_rename_test/A/%d", id);
  ksprintf(pathB, "_rename_test/B/%d", id);
  ksprintf(pathC, "_rename_test/C/%d", id);
  create_file_with_data(pathA, "");

  for (i = 0; i < LOCK_ORDER_THREAD_ITERS; ++i) {
    if (id % 2 == 0) {
      result = vfs_rename(pathA, pathB);
      if (result) break;
      result = vfs_rename(pathB, pathC);
      if (result) break;
      result = vfs_rename(pathC, pathA);
      if (result) break;
    } else {
      result = vfs_rename(pathA, pathB);
      if (result) break;
      result = vfs_rename(pathB, pathA);
      if (result) break;
    }
  }
  KEXPECT_EQ(0, result);
  KEXPECT_EQ(0, vfs_unlink(pathA));
  return NULL;
}

const int ANCESTOR_THREAD_ITERS = 100 * THREAD_SAFETY_MULTIPLIER;
static void* ancestor_thread_funcA(void* arg) {
  for (int i = 0; i < ANCESTOR_THREAD_ITERS; ++i) {
    vfs_rename("_rename_test/A", "_rename_test/C/D/x");
    vfs_rename("_rename_test/C/D/x", "_rename_test/A");
  }
  return NULL;
}

static void* ancestor_thread_funcB(void* arg) {
  for (int i = 0; i < ANCESTOR_THREAD_ITERS; ++i) {
    vfs_rename("_rename_test/C", "_rename_test/A/B/y");
    vfs_rename("_rename_test/A/B/y", "_rename_test/C");
  }
  return NULL;
}

static void rename_thread_test(void) {
  KTEST_BEGIN("vfs_rename(): destination always visible (atomic)");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_symlink("A", "_rename_test/link"));
  create_file_with_data("_rename_test/A/C", "");
  create_file_with_data("_rename_test/B/C", "");

  const int NUM_OPENERS = 5;
  kthread_t threads[1 + NUM_OPENERS];
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &rename_symlink_func, NULL));
  for (int i = 0; i < NUM_OPENERS; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[1 + i], &rename_symlink_open_func,
                                     NULL));
  }
  for (int i = 0; i < 1 + NUM_OPENERS; ++i) {
    kthread_join(threads[i]);
  }

  KEXPECT_EQ(0, vfs_unlink("_rename_test/A/C"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/B/C"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));
  KEXPECT_EQ(0, vfs_unlink("_rename_test/link"));


  KTEST_BEGIN("vfs_rename(): lock order test");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/C", VFS_S_IRWXU));

  for (intptr_t i = 0; i < NUM_OPENERS; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[i], &lock_order_func, (void*)i));
  }
  for (int i = 0; i < NUM_OPENERS; ++i) {
    kthread_join(threads[i]);
  }
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/A"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/B"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/C"));


  KTEST_BEGIN("vfs_rename(): ancestor race condition test");
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/A/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/C", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("_rename_test/C/D", VFS_S_IRWXU));
  KEXPECT_EQ(0, proc_thread_create(&threads[0], ancestor_thread_funcA, NULL));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], ancestor_thread_funcB, NULL));
  kthread_join(threads[0]);
  kthread_join(threads[1]);

  const char* kPaths[] = {
    "_rename_test/A/B/y/D",
    "_rename_test/C/D/x/B",
    "_rename_test/A/B/y",
    "_rename_test/C/D/x",
    "_rename_test/A/B",
    "_rename_test/C/D",
    "_rename_test/A",
    "_rename_test/C",
  };
  int count = 0;
  for (unsigned int i = 0; i < sizeof(kPaths) / sizeof(const char*); ++i) {
    if (vfs_rmdir(kPaths[i]) == 0) count++;
  }
  KEXPECT_EQ(4, count);
}

static void rename_test(void) {
  rename_test_state_t s;
  rename_testA(&s);
  rename_testB(&s);
  rename_testC(&s);
  rename_testD(&s);
  rename_testE(&s);
  rename_testF(&s);
  rename_testG(&s);
  rename_testH(&s);
  rename_testI();
  rename_testJ();
  rename_testK();
  rename_symlink_test();
  rename_thread_test();

  // Tests -
  //  - someone renames into a directory that is simultaneously rmdir'd()
  //  - other interesting race conditions
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirA"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test/dirB"));
  KEXPECT_EQ(0, vfs_rmdir("_rename_test"));
}

typedef struct {
  kspinlock_t lock;
  int creations;
  int num_dests;
  int rename_successes;
  int rename_attempts;
  bool* done;
} rename_simultaneous_race_test_args;

static void* rename_simultaneous_race_test_func1(void* arg) {
  rename_simultaneous_race_test_args* args =
      (rename_simultaneous_race_test_args*)arg;
  for (int i = 0; i < args->creations; ++i) {
    // Usually create new files, but occasionally link existing ones.
    if (i % 5 != 0) {
      create_file("thread_safety_test/A/src", "rwxrwxrwx");
    } else {
      int result;
      do {
        result =
            vfs_link("thread_safety_test/file1", "thread_safety_test/A/src");
      } while (result == -EINJECTEDFAULT);
      KEXPECT_EQ(0, result);
    }
    // Occasionally create a new dest file as well.
    if (i % 3 == 0) {
      char dest_path[40];
      ksprintf(dest_path, "thread_safety_test/B/dst%d",
               (i % 7) % args->num_dests);
      create_file(dest_path, "rwxrwxrwx");
    }
    apos_stat_t stat;
    while (vfs_lstat("thread_safety_test/A/src", &stat) != -ENOENT) {
      scheduler_yield();
    }
  }
  return 0;
}

static void* rename_simultaneous_race_test_func2(void* arg) {
  rename_simultaneous_race_test_args* args =
      (rename_simultaneous_race_test_args*)arg;
  char dest_path[40];
  const char* dest_dir = (kthread_current_thread()->id % 2) ? "A" : "B";
  ksprintf(dest_path, "thread_safety_test/%s/dst%d", dest_dir,
           kthread_current_thread()->id % args->num_dests);
  // TODO(aoates): use lock, atomic, or notification.
  bool me_done = false;
  uint32_t rand = fnv_hash((uint32_t)kthread_current_thread()->id);
  while (!me_done) {
    // Once the creating thread finishes, try one final rename.
    if (*(args->done)) me_done = true;

    rand = fnv_hash(rand);
    int result;
    // Occasionally try a normal unlink() rather than a rename.
    if (rand % 5 == 0) {
      result = vfs_unlink("thread_safety_test/A/src");
    } else {
      // We have to use the _unique() version --- otherwise a same-to-same-vnode
      // rename would register as a successful rename and screw up our
      // creation-vs-rename count.  This occurs only rarely, but introduces
      // spurious failures if the iterations on this test are cranked up.
      result = vfs_rename_unique("thread_safety_test/A/src", dest_path);
    }
    if (result < 0 && result != -ERENAMESAMEVNODE &&
        result != -EINJECTEDFAULT) {
      KEXPECT_EQ(-ENOENT, result);
    }
    kspin_lock(&args->lock);
    args->rename_attempts++;
    if (result == 0) args->rename_successes++;
    kspin_unlock(&args->lock);

    // Occasionally unlink the dest as well.
    if (rand % 2 == 0) {
      result = vfs_unlink(dest_path);
      if (result < 0 && result != -EINJECTEDFAULT) {
        KEXPECT_EQ(-ENOENT, result);
      }
    }
    scheduler_yield();
  }
  return 0;
}

// A basic rename race test that has a bunch of threads all trying to rename the
// same file.  We verify that only one succeeds each time.
// TODO(aoates): consider a more advanced version of this that also includes
// renaming directories.
static void rename_simultaneous_race_test(void) {
  const int kNumRenameThreads = THREAD_SAFETY_TEST_THREADS;
  KTEST_BEGIN("vfs_rename() simultaneous race test");
  kthread_t creating_thread, chaos_thread[2];
  kthread_t rename_threads[kNumRenameThreads];

  // Set things up.
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test", 0));
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test/A", 0));
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test/B", 0));
  create_file("thread_safety_test/file1", "rwxrwxrwx");

  int old_ramfs_fault_pct;
  if (kstrcmp(vfs_get_root_fs()->fstype, "ramfs") == 0) {
    old_ramfs_fault_pct = ramfs_set_fault_percent(vfs_get_root_fs(), 1);
  }

  chaos_args_t chaos_args[2];
  chaos_args[0].path = "thread_safety_test/A";
  chaos_args[0].done = false;
  chaos_args[1].path = "thread_safety_test/B";
  chaos_args[1].done = false;
  for (int i = 0; i < 2; ++i) {
    KEXPECT_EQ(
        0, proc_thread_create(&chaos_thread[i], &chaos_helper, &chaos_args[i]));
  }

  rename_simultaneous_race_test_args args;
  args.done = &chaos_args[0].done;
  args.lock = KSPINLOCK_NORMAL_INIT;
  args.rename_attempts = args.rename_successes = 0;
  args.creations = THREAD_SAFETY_TEST_ITERS / 10;
  args.num_dests = kNumRenameThreads / 10;
  KEXPECT_EQ(0,
             proc_thread_create(&creating_thread,
                                &rename_simultaneous_race_test_func1, &args));

  for (int i = 0; i < kNumRenameThreads; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&rename_threads[i],
                                  &rename_simultaneous_race_test_func2, &args));
  }

  kthread_join(creating_thread);
  for (int i = 0; i < 2; ++i) {
    chaos_args[i].done = true;
    kthread_join(chaos_thread[i]);
  }
  for (int i = 0; i < kNumRenameThreads; ++i) {
    kthread_join(rename_threads[i]);
  }

  if (kstrcmp(vfs_get_root_fs()->fstype, "ramfs") == 0) {
    ramfs_set_fault_percent(vfs_get_root_fs(), old_ramfs_fault_pct);
  }

  // At the end of the day, we should have been able to rename (or unlink)
  // successfully exactly as many times as we created a file.
  KEXPECT_EQ(args.creations, args.rename_successes);
  klogf("rename race test: %d successful renames out of %d attempts\n",
        args.rename_successes, args.rename_attempts);
  KEXPECT_EQ(-ENOENT, vfs_unlink("thread_safety_test/A/src"));

  // Clean up
  KEXPECT_EQ(0, vfs_unlink("thread_safety_test/file1"));
  char dest_path[40];
  for (int i = 0; i < args.num_dests; ++i) {
    ksprintf(dest_path, "thread_safety_test/A/dst%d", i);
    vfs_unlink(dest_path);
    ksprintf(dest_path, "thread_safety_test/B/dst%d", i);
    vfs_unlink(dest_path);
  }
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test/A"));
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test/B"));
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test"));
}

typedef struct {
  kspinlock_t lock;
  int num_dests;
  int unlinks_target;
  int unlink_successes;
  int unlink_attempts;
  int link_successes;
  int link_attempts;
  bool* done;
} link_simultaneous_race_test_args;

// Have several length paths to add some randomness to first-fitting-dirent
// logic.  Have both same directory as the source, and a different one.
#define kNumLinkSimulDestRoots 6
const char* kLinkSimulDestRoots[kNumLinkSimulDestRoots] = {
  "thread_safety_test/dest.a",
  "thread_safety_test/dest.aaaaaa",
  "thread_safety_test/dest.aaaaaaaaaaa",
  "thread_safety_test/B/dest.a",
  "thread_safety_test/B/dest.aaaaaa",
  "thread_safety_test/B/dest.aaaaaaaaaaa",
};

static void* link_simultaneous_race_test_func1(void* arg) {
  link_simultaneous_race_test_args* args =
      (link_simultaneous_race_test_args*)arg;
  uint32_t rand = fnv_hash((uint32_t)(intptr_t)args);
  char dest[100];
  while (args->unlink_successes < args->unlinks_target) {
    rand = fnv_hash(rand);
    const char* root = kLinkSimulDestRoots[rand % kNumLinkSimulDestRoots];
    rand = fnv_hash(rand);
    ksprintf(dest, "%s.%d", root, rand % args->num_dests);
    int result = vfs_unlink(dest);

    // Only reader/writer of these fields, no need to lock.
    args->unlink_attempts++;
    if (result == 0) args->unlink_successes++;
    scheduler_yield();
  }
  return 0;
}

static void* link_simultaneous_race_test_func2(void* arg) {
  link_simultaneous_race_test_args* args =
      (link_simultaneous_race_test_args*)arg;
  const char* kSourcePaths[2] = {"thread_safety_test/file1",
                                 "thread_safety_test/file2"};

  // TODO(aoates): use lock, atomic, or notification.
  uint32_t rand = fnv_hash((uint32_t)kthread_current_thread()->id);
  char dest[100];
  while (!(*args->done)) {
    rand = fnv_hash(rand);
    const char* src = kSourcePaths[rand % 2];
    rand = fnv_hash(rand);
    const char* root = kLinkSimulDestRoots[rand % kNumLinkSimulDestRoots];
    rand = fnv_hash(rand);
    ksprintf(dest, "%s.%d", root, rand % args->num_dests);

    int result = vfs_link(src, dest);
    if (result < 0 && result != -EINJECTEDFAULT) {
      KEXPECT_EQ(-EEXIST, result);
    }
    kspin_lock(&args->lock);
    args->link_attempts++;
    if (result == 0) args->link_successes++;
    kspin_unlock(&args->lock);

    scheduler_yield();
  }
  return 0;
}

// A basic link race test that has a bunch of threads all trying to link the
// same source and destination paths.  We verify that only one succeeds each
// time.  This should test both fan-in and fan-out scenarios.
static void link_simultaneous_race_test(void) {
  // We want some contention on the destination files, but not complete fan-in.
  // More contention stresses single-node locking, while less contention
  // stresses parent node locking.
  const int kNumDests = 5;
  const int kNumLinkThreads = THREAD_SAFETY_TEST_THREADS;
  KTEST_BEGIN("vfs_link() simultaneous race test");
  // Note: we specifically _don't_ want chaos threads that lock files for this
  // test --- it introduces sequencing between the threads that makes the test
  // ineffective.
  kthread_t creating_thread;
  kthread_t link_threads[kNumLinkThreads];

  // Set things up.  We pre-create all the destination files to ensure that the
  // number of successful links should exactly equal the number of unlinks.
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test", 0));
  KEXPECT_EQ(0, vfs_mkdir("thread_safety_test/B", 0));
  create_file("thread_safety_test/file1", "rwxrwxrwx");
  create_file("thread_safety_test/file2", "rwxrwxrwx");
  char dest[100];

  bool done = false;
  link_simultaneous_race_test_args args;
  args.done = &done;
  args.lock = KSPINLOCK_NORMAL_INIT;
  args.unlink_successes = args.unlink_attempts = args.link_attempts =
      args.link_successes = 0;
  args.unlinks_target = THREAD_SAFETY_TEST_ITERS / 10;
  args.num_dests = kNumDests;
  KEXPECT_EQ(0, proc_thread_create(&creating_thread,
                                   &link_simultaneous_race_test_func1, &args));

  for (int i = 0; i < kNumLinkThreads; ++i) {
    KEXPECT_EQ(0,
               proc_thread_create(&link_threads[i],
                                  &link_simultaneous_race_test_func2, &args));
  }

  kthread_join(creating_thread);
  done = true;
  for (int i = 0; i < kNumLinkThreads; ++i) {
    kthread_join(link_threads[i]);
  }

  for (int i = 0; i < kNumLinkSimulDestRoots; ++i) {
    for (int j = 0; j < kNumDests; ++j) {
      ksprintf(dest, "%s.%d", kLinkSimulDestRoots[i], j);
      args.unlink_attempts++;
      if (vfs_unlink(dest) == 0) args.unlink_successes++;
    }
  }

  // At the end of the day, we should have been able to link successfully
  // exactly as many times as we unlinked.
  KEXPECT_EQ(args.unlink_successes, args.link_successes);
  klogf(
      "link race test: %d successful links out of %d attempts; %d unlinks out "
      "of %d attempts\n",
      args.link_successes, args.link_attempts, args.unlink_successes,
      args.unlink_attempts);

  // Clean up.
  KEXPECT_EQ(0, vfs_unlink("thread_safety_test/file1"));
  KEXPECT_EQ(0, vfs_unlink("thread_safety_test/file2"));
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test/B"));
  KEXPECT_EQ(0, vfs_rmdir("thread_safety_test"));
}

static void* fd_concurrent_close_test_helper(void* arg) {
  int fd = (intptr_t)arg;
  char buf[10];
  int result = vfs_read(fd, buf, 10);
  return (void*)(intptr_t) result;
}

// A test for closing a file descriptor in one thread concurrently with a
// blocking operation in another thread.  Ideally we'd have such a test for
// every blocking operation, but for now just use a pipe as an examplar.
//
// This is undefined behavior from the userspace perspective, but we need to
// ensure we clean up properly.
// TODO(aoates): write a userpsace tests for this when we support multiple
// threads per process in userspace.
static void fd_concurrent_close_test(void) {
  KTEST_BEGIN("vfs: closing fd during blocking pipe read");

  int fds[2];
  KEXPECT_EQ(0, vfs_pipe(fds));

  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &fd_concurrent_close_test_helper,
                                   (void*)(intptr_t)fds[0]));

  // Ensure the thread gets into the read() call.
  for (int i = 0; i < 10; i++) scheduler_yield();
  KEXPECT_EQ(0, vfs_close(fds[0]));
  for (int i = 0; i < 10; i++) scheduler_yield();
  KEXPECT_EQ(0, vfs_close(fds[1]));
  KEXPECT_EQ(0, (intptr_t)kthread_join(thread));
}

static void* multithread_path_walk_deadlock_test_worker(void* arg) {
  uint32_t rand = fnv_hash(get_time_ms());
  rand = fnv_hash_concat(rand, kthread_current_thread()->id);
  const char* paths[] = {
    "A/B/C",
    "A/../A/B/C",
    "A/B/../../A/B/C",
    "A/B/../B/C",
    "A/./B/C",
    "A/../A/B/./C",
  };
  const int kNumPaths = sizeof(paths) / sizeof(const char*);
  for (int i = 0; i < 20 * CONCURRENCY_TEST_ITERS_MULT; ++i) {
    int path_idx = rand % kNumPaths;
    rand = fnv_hash(rand);
    int fd = vfs_open(paths[path_idx], 0);
    KEXPECT_GE(fd, 0);
    KEXPECT_EQ(0, vfs_close(fd));
    if (rand % 10 == 0) scheduler_yield();
    rand = fnv_hash(rand);
  }
  return NULL;
}

static void multithread_path_walk_deadlock_test(void) {
  KTEST_BEGIN("vfs: multiple threads walking cyclical paths");
  const int kNumThreads = 5 * CONCURRENCY_TEST_THREADS_MULT;
  kthread_t threads[kNumThreads];
  KEXPECT_EQ(0, vfs_mkdir("A", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mkdir("A/B", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("A/B/C", VFS_S_IFREG | VFS_S_IRWXU, 0));
  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(
        0, proc_thread_create(
               &threads[i], &multithread_path_walk_deadlock_test_worker, NULL));
  }
  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(NULL, kthread_join(threads[i]));
  }

  KEXPECT_EQ(0, vfs_unlink("A/B/C"));
  KEXPECT_EQ(0, vfs_rmdir("A/B"));
  KEXPECT_EQ(0, vfs_rmdir("A"));
}

static void* multithread_vnode_get_test_worker(void* arg) {
  // TODO(aoates): enable preemption here when safe for VFS.
  uint32_t rand = fnv_hash(get_time_ms());
  rand = fnv_hash_concat(rand, kthread_current_thread()->id);
  const int* arg_array = (int*)arg;
  const int num_vnodes = *arg_array;
  arg_array++;
  for (int i = 0; i < 100 * CONCURRENCY_TEST_ITERS_MULT; ++i) {
    int vnode_num = arg_array[rand % num_vnodes];
    rand = fnv_hash(rand);
    vnode_t* vnode = vfs_get(vfs_get_root_fs(), vnode_num);
    vfs_put(vnode);
  }
  return NULL;
}

static void multithread_vnode_get_test(void) {
  KTEST_BEGIN("vfs: multiple threads getting and putting vnodes (2 threads)");
  // Only 2 threads to ensure we're frequently exercising the refcount==0 case.
  const int kNumThreadsA = 2;
  const int kNumThreadsB = 10 * CONCURRENCY_TEST_THREADS_MULT;
  const int kNumVnodes = 5;
  kthread_t threads[kNumThreadsB];
  KEXPECT_EQ(0, vfs_mkdir("vnode_tests", VFS_S_IRWXU));
  int vnodes[kNumVnodes + 1];
  vnodes[0] = kNumVnodes;

  char path[20];
  apos_stat_t stat;
  for (int i = 0; i < kNumVnodes; ++i) {
    ksprintf(path, "vnode_tests/v%d", i);
    create_file(path, RWX);
    KEXPECT_EQ(0, vfs_stat(path, &stat));
    vnodes[i + 1] = stat.st_ino;
  }

  for (int i = 0; i < kNumThreadsA; ++i) {
    KEXPECT_EQ(0, proc_thread_create(
                      &threads[i], &multithread_vnode_get_test_worker, vnodes));
  }
  for (int i = 0; i < kNumThreadsA; ++i) {
    KEXPECT_EQ(NULL, kthread_join(threads[i]));
  }

  // Run the test again, but with many threads to exercise refcounting logic.
  KTEST_BEGIN("vfs: multiple threads getting and putting vnodes (N threads)");

  for (int i = 0; i < kNumThreadsB; ++i) {
    KEXPECT_EQ(0, proc_thread_create(
                      &threads[i], &multithread_vnode_get_test_worker, vnodes));
  }
  for (int i = 0; i < kNumThreadsB; ++i) {
    KEXPECT_EQ(NULL, kthread_join(threads[i]));
  }

  for (int i = 0; i < kNumVnodes; ++i) {
    ksprintf(path, "vnode_tests/v%d", i);
    KEXPECT_EQ(0, vfs_unlink(path));
  }
  KEXPECT_EQ(0, vfs_rmdir("vnode_tests"));
}

static void* multithread_vnode_get_put_race_test_func(void* arg) {
  const char kPath[] = "vnode_tests/file";
  vnode_t* node = NULL;
  int result = lookup_existing_path(kPath, lookup_opt(false), &node);
  KEXPECT_EQ(0, result);
  if (result != 0) return 0x0;

  fs_t* const vnode_fs = node->fs;
  const int vnode_num = node->num;
  vfs_put(node);

  const int iters = (intptr_t)arg;
  uint32_t rand = fnv_hash((uint32_t)(intptr_t)&vnode_fs);
  for (int i = 0; i < iters; ++i) {
    node = vfs_get(vnode_fs, vnode_num);
    KEXPECT_NE(node, NULL);
    if (!node) return 0x0;
    KEXPECT_EQ(vnode_fs, node->fs);
    KEXPECT_EQ(vnode_num, node->num);
    KEXPECT_EQ(VNODE_REGULAR, node->type);

    // Try and set up the race.
    if (atomic_load_relaxed(&node->refcount) > 1) scheduler_yield();

    kmutex_lock(&node->mutex);
    node->uid++;
    kmutex_unlock(&node->mutex);
    vfs_put(node);

    // This yield is necessary for the test to catch the get/put race bug.
    // Randomizing isn't strictly necessary, but makes it more effective.
    rand = fnv_hash(rand);
    if (rand % 2 == 0) scheduler_yield();
  }
  return 0x0;
}

// A test that ensures vfs_get() and vfs_put() ensure atomicity between them.
static void multithread_vnode_get_put_race_test(void) {
  KTEST_BEGIN("vfs: multiple threads getting and putting a single vnode");
  // Only 2 threads to ensure we're frequently exercising the refcount==0 case.
  const int kNumThreads = 2;
  const int kIters = THREAD_SAFETY_TEST_ITERS;
  KEXPECT_EQ(0, vfs_mkdir("vnode_tests", VFS_S_IRWXU));
  create_file("vnode_tests/file", RWX);

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("vnode_tests/file", &stat));
  apos_uid_t starting_uid = stat.st_uid;

  kthread_t threads[kNumThreads];
  for (int i = 0; i < kNumThreads; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&threads[i],
                                     &multithread_vnode_get_put_race_test_func,
                                     (void*)(intptr_t)kIters));
  }
  for (int i = 0; i < kNumThreads; ++i) {
    kthread_join(threads[i]);
  }

  KEXPECT_EQ(0, vfs_stat("vnode_tests/file", &stat));
  KEXPECT_EQ(stat.st_uid, starting_uid + kIters * kNumThreads);

  // Cleanup.
  KEXPECT_EQ(0, vfs_unlink("vnode_tests/file"));
  KEXPECT_EQ(0, vfs_rmdir("vnode_tests"));
}

typedef enum {
  TEST_CREATE_MKDIR = 1,
  TEST_CREATE_MKNOD = 2,
  TEST_CREATE_SYMLINK = 3,
  TEST_CREATE_OPEN = 4,
} test_create_type_t;

typedef struct {
  bool done;
  test_create_type_t type;
} mtcdrt_args_t;

static void* multithread_create_delete_race_test_make_func(void* arg) {
  mtcdrt_args_t* args = (mtcdrt_args_t*)arg;
  // TODO(aoates): use atomic or notification.
  while (!args->done) {
    int result;
    switch (args->type) {
      case TEST_CREATE_MKDIR:
        result = vfs_mkdir("vfs_race_test/dir", VFS_S_IRWXU);
        break;
      case TEST_CREATE_MKNOD:
        result = vfs_mknod("vfs_race_test/file", VFS_S_IFREG | VFS_S_IRWXU,
                           kmakedev(0, 0));
        break;
      case TEST_CREATE_SYMLINK:
        result = vfs_symlink("abc", "vfs_race_test/link");
        break;
      case TEST_CREATE_OPEN:
        result = vfs_open("vfs_race_test/file", VFS_O_CREAT | VFS_O_RDONLY,
                          VFS_S_IRWXU);
        if (result == 0) {
          vfs_close(result);
        }
        break;
    }
    if (result != 0) {
      KEXPECT_EQ(-EEXIST, result);
    }
    // TODO(aoates): remove this when preemption or randomized scheduler is in.
    scheduler_yield();
  }
  return 0x0;
}

// Helper to do a create/delete race test using vfs_unlink() to remove the path.
static void do_create_unlink_race_test(int iters, const char* path,
                                       test_create_type_t type) {
  kthread_t create_thread;
  mtcdrt_args_t args;
  args.done = false;
  args.type = type;
  KEXPECT_EQ(0, proc_thread_create(
                    &create_thread,
                    &multithread_create_delete_race_test_make_func, &args));

  int deletions = 0;
  while (deletions < iters) {
    int result = vfs_unlink(path);
    if (result == 0) {
      deletions++;
    } else {
      KEXPECT_EQ(-ENOENT, result);
    }
    // TODO(aoates): remove this when preemption or randomized scheduler is in.
    scheduler_yield();
  }
  args.done = true;
  kthread_join(create_thread);
  vfs_unlink(path);
}

// A series of tests where one thread continuously creates entries (files,
// directories, symlinks, etc), while another deletes them.
static void multithread_create_delete_race_test(void) {
  KTEST_BEGIN("vfs: create+delete race tests (mkdir/rmdir)");
  const int kIters = THREAD_SAFETY_TEST_ITERS / 2;
  KEXPECT_EQ(0, vfs_mkdir("vfs_race_test", VFS_S_IRWXU));

  kthread_t create_thread;
  mtcdrt_args_t args;
  args.done = false;
  args.type = TEST_CREATE_MKDIR;
  KEXPECT_EQ(0, proc_thread_create(
                    &create_thread,
                    &multithread_create_delete_race_test_make_func, &args));

  int deletions = 0;
  while (deletions < kIters) {
    int result = vfs_rmdir("vfs_race_test/dir");
    if (result == 0) {
      deletions++;
    } else {
      KEXPECT_EQ(-ENOENT, result);
    }
    // TODO(aoates): remove this when preemption or randomized scheduler is in.
    scheduler_yield();
  }
  args.done = true;
  kthread_join(create_thread);
  vfs_rmdir("vfs_race_test/dir");


  KTEST_BEGIN("vfs: create+delete race tests (mknod/unlink)");
  do_create_unlink_race_test(kIters, "vfs_race_test/file", TEST_CREATE_MKNOD);

  KTEST_BEGIN("vfs: create+delete race tests (symlink/unlink)");
  do_create_unlink_race_test(kIters, "vfs_race_test/link", TEST_CREATE_SYMLINK);

  KTEST_BEGIN("vfs: create+delete race tests (open/unlink)");
  do_create_unlink_race_test(kIters, "vfs_race_test/file", TEST_CREATE_OPEN);

  // TODO(aoates): do similar tests for link() and rename(). These are more
  // complicated operations that wouldn't manifest bugs as simply as the above
  // creation functions, so a more thorough test would be needed to be
  // comprehensive.

  KEXPECT_EQ(0, vfs_rmdir("vfs_race_test"));
}

// TODO(aoates): multi-threaded test for creating a file in directory that is
// being unlinked.  There may currently be a race condition where a new entry is
// creating while the directory is being deleted.

// TODO(aoates): preemption safety tests:
//  - FD manipulation (simultaneous lookup, opening, closing, dup, dup2, etc).
//    Must be from multiple processes as well as threads!

void vfs_test(void) {
  KTEST_SUITE_BEGIN("vfs test");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  if (kstrcmp(vfs_get_root_fs()->fstype, "ramfs") == 0) {
    ramfs_enable_blocking(vfs_get_root_fs());
  }

  const size_t kBufSize = 100;
  char orig_cwd[kBufSize];
  KEXPECT_GT(vfs_getcwd(orig_cwd, kBufSize), 0);
  KEXPECT_EQ(0, vfs_chdir("/"));

  g_orig_root_vnode_refcount = vfs_get_vnode_refcount_for_path("/");
  const kmode_t orig_umask = proc_umask(0);

  dev_test();

  open_test();
  mkdir_test();
  file_table_reclaim_test();
  vfs_open_thread_safety_test();
  vfs_open_create_race_test();
  vfs_open_get_fifo_socket_test();
  unlink_test();
  unlink_race_test();
  rmdir_race_test();
  get_path_test();
  cwd_test();
  rw_test();
  write_large_test();
  write_thread_test();
  rw_mode_test();
  getdents_test();
  seek_test();
  get_bad_inode_test();
  create_thread_test();
  unlink_open_file_test();
  unlink_open_directory_test();
  create_in_unlinked_directory();
  memobj_test();

  mknod_test();
  mksocket_test();
  block_device_test();

  fs_dev_test();
  lstat_test();
  stat_test();
  initial_owner_test();
  lchown_test();
  chown_test();

  mode_flags_test();
  chmod_test();
  open_mode_test();
  mkdir_mode_test();
  mknod_mode_test();

  symlink_test();
  readlink_test();

  dup_test();
  dup2_test();

  pipe_test();
  reverse_path_test();

  ftruncate_test();
  truncate_test();
  open_truncate_test();
  truncate_filetype_test();
  append_test();
  excl_test();
  o_directory_test();
  o_nofollow_test();
  o_cloexec_test();

  link_test();
  link_testB();
  rename_test();

  rename_simultaneous_race_test();
  link_simultaneous_race_test();
  fd_concurrent_close_test();
  multithread_path_walk_deadlock_test();
  multithread_vnode_get_test();
  multithread_vnode_get_put_race_test();
  multithread_create_delete_race_test();

  proc_umask(orig_umask);

  umask_test();

  if (kstrcmp(vfs_get_root_fs()->fstype, "ramfs") == 0) {
    ramfs_disable_blocking(vfs_get_root_fs());
  }

  KTEST_BEGIN("vfs: vnode leak verification");
  block_cache_clear_unpinned();
  EXPECT_VNODE_REFCOUNT(g_orig_root_vnode_refcount, "/");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());

  KEXPECT_EQ(0, vfs_chdir(orig_cwd));
}
