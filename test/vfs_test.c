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
#include "proc/process.h"
#include "proc/scheduler.h"
#include "test/ktest.h"
#include "vfs/ramfs.h"
#include "vfs/util.h"
#include "vfs/vfs.h"

// Increase this to make thread safety tests run longer.
#define THREAD_SAFETY_MULTIPLIER 1

#define EXPECT_VNODE_REFCOUNT(count, path) \
    KEXPECT_EQ((count), vfs_get_vnode_refcount_for_path(path))

// Helper method to create a file for a test.
static void create_file(const char* path) {
  const int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR);
  KASSERT(fd >= 0);
  vfs_close(fd);
}

static void create_file_with_data(const char* path, const char* data) {
  const int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR);
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

// Helper method that verifies that the given file can be created (then unlinks
// it).
static void EXPECT_CAN_CREATE_FILE(const char* path) {
  const int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    vfs_close(fd);
    vfs_unlink(path);
  }
}

// Helper method that verifies the given file exists.
static void EXPECT_FILE_EXISTS(const char* path) {
  // The file should still exist.
  const int fd = vfs_open(path, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    KEXPECT_EQ(0, vfs_close(fd));
  }
}

static void EXPECT_FILE_DOESNT_EXIST(const char* path) {
  EXPECT_CAN_CREATE_FILE(path);
}

// Test that we correctly refcount parent directories when calling vfs_open().
static void open_parent_refcount_test() {
  KTEST_BEGIN("vfs_open(): parent refcount test");
  KEXPECT_EQ(0, vfs_mkdir("/ref_dir1"));
  KEXPECT_EQ(0, vfs_mkdir("/ref_dir1/dir2"));

  const int fd1 = vfs_open("/ref_dir1/dir2/test1", VFS_O_CREAT | VFS_O_RDWR);
  KEXPECT_GE(fd1, 0);

  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(1, "/ref_dir1/dir2/test1");

  const int fd2 = vfs_open("/ref_dir1/dir2/test1", VFS_O_CREAT | VFS_O_RDWR);
  KEXPECT_GE(fd2, 0);

  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(2, "/ref_dir1/dir2/test1");

  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(0, vfs_close(fd2));

  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2/test1");

  // Clean up.
  vfs_unlink("/ref_dir1/dir2/test1");
  vfs_rmdir("/ref_dir1/dir2");
  vfs_rmdir("/ref_dir1");
}

// Test calling vfs_open() on a directory.
static void open_dir_test() {
  KTEST_BEGIN("vfs_open(): open directory (read-only)");
  KEXPECT_EQ(0, vfs_mkdir("/dir1"));
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

static void open_test() {
  KTEST_BEGIN("vfs_open() test");

  vfs_log_cache();
  KEXPECT_EQ(-ENOENT, vfs_open("/test1", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(-ENOENT, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(0, vfs_open("/test1", VFS_O_CREAT | VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(1, vfs_open("/test1", VFS_O_CREAT | VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(2, vfs_open("/test2", VFS_O_CREAT | VFS_O_RDWR));
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
  KEXPECT_EQ(1, vfs_open("/test3", VFS_O_CREAT | VFS_O_RDWR));
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
  EXPECT_VNODE_REFCOUNT(1, "/");
  KEXPECT_EQ(-ENOTDIR, vfs_open("/test1/test2", VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(1, "/");
  KEXPECT_EQ(-ENOTDIR, vfs_open("/test1/test2", VFS_O_CREAT | VFS_O_RDWR));
  EXPECT_VNODE_REFCOUNT(1, "/");

  open_parent_refcount_test();
  open_dir_test();

  KTEST_BEGIN("vfs_open(): invalid mode");
  KEXPECT_EQ(-EINVAL, vfs_open("/test1", VFS_O_RDWR | VFS_O_WRONLY));

  // Clean up.
  KEXPECT_EQ(0, vfs_unlink("/test1"));
  KEXPECT_EQ(0, vfs_unlink("/test2"));
  KEXPECT_EQ(0, vfs_unlink("/test3"));
}

static void mkdir_test() {
  KTEST_BEGIN("vfs_mkdir() test");

  // Make sure we have some normal files around.
  const int test1_fd = vfs_open("/test1", VFS_O_CREAT | VFS_O_RDWR);
  KEXPECT_GE(test1_fd, 0);

  KEXPECT_EQ(-EEXIST, vfs_mkdir("/"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/test1"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");

  KEXPECT_EQ(-ENOTDIR, vfs_mkdir("/test1/dir1"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");

  KTEST_BEGIN("regular mkdir()");
  KEXPECT_EQ(0, vfs_mkdir("/dir1"));
  KEXPECT_EQ(0, vfs_mkdir("/dir2"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir2"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KTEST_BEGIN("nested mkdir()");
  KEXPECT_EQ(-ENOENT, vfs_mkdir("/dir1/dir1a/dir1b"));
  KEXPECT_EQ(0, vfs_mkdir("/dir1/dir1a"));
  KEXPECT_EQ(0, vfs_mkdir("/dir1/dir1a/dir1b"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a/dir1b");

  // TODO(aoates): better testing for . and ...
  // TODO(aoates): test '.' and '..' at the end of paths
  KTEST_BEGIN("crappy '.' and '..' tests");
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/."));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/.."));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/./dir1"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/../dir1"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/../../../dir1"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1/./././dir1a"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1/../dir2/../dir1/./dir1a/dir1b/../dir1b"));

  // TODO(aoates): create files in the directories, open them
  // TODO(aoates): test '.' and '..' links!
  // TODO(aoates): test multiple slashes and traling slashes
  // TODO(aoates): test unlink()'ing a directory
  // TODO(aoates): you can't unlink '.' or '..'

  KTEST_BEGIN("rmdir(): directory or path doesn't exist");
  KEXPECT_EQ(-ENOENT, vfs_rmdir("/boo"));
  KEXPECT_EQ(-ENOENT, vfs_rmdir("/dir1/boo"));
  KEXPECT_EQ(-ENOENT, vfs_rmdir("/boo/boo2"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KTEST_BEGIN("rmdir(): not a directory");
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("/test1"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  // TODO(aoates): test nested not-a-dir

  KTEST_BEGIN("rmdir(): root directory");
  KEXPECT_EQ(-EPERM, vfs_rmdir("/"));
  EXPECT_VNODE_REFCOUNT(1, "/");

  KTEST_BEGIN("rmdir(): invalid paths");
  KEXPECT_EQ(-EINVAL, vfs_rmdir("/dir1/dir1a/."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/dir1a/dir1b/.."));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a/dir1b");

  KTEST_BEGIN("rmdir(): not empty");
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/dir1a"));
  EXPECT_VNODE_REFCOUNT(1, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  // Actually test it (and cleanup the directories we created).
  KTEST_BEGIN("rmdir(): working");
  KEXPECT_EQ(-0, vfs_rmdir("/dir2"));
  KEXPECT_EQ(-0, vfs_rmdir("/dir1/dir1a/.././dir1a/dir1b"));
  KEXPECT_EQ(-0, vfs_rmdir("/dir1/dir1a/"));
  KEXPECT_EQ(-0, vfs_rmdir("///dir1//"));

  // Should still fail even though it's empty.
  KEXPECT_EQ(-EPERM, vfs_rmdir("/"));

  // Cleanup.
  vfs_close(test1_fd);
  KEXPECT_EQ(0, vfs_unlink("/test1"));
}

// Test repeatedly opening and closing a file to make sure that we reclaim FDs
// and file table entries correctly.
static void file_table_reclaim_test() {
  KTEST_BEGIN("file table reclaim test");
  const char kTestDir[] = "/reclaim_test/";
  const char kTestFile[] = "/reclaim_test/test1";
  KEXPECT_EQ(0, vfs_mkdir(kTestDir));
  int files_opened = 0;
  for (int i = 0; i < VFS_MAX_FILES * 2; ++i) {
    const int fd = vfs_open(kTestFile, VFS_O_CREAT | VFS_O_RDWR);
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
                      VFS_O_CREAT | VFS_O_RDWR);
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

static void vfs_open_thread_safety_test() {
  KTEST_BEGIN("vfs_open() thread safety test");
  kthread_t threads[THREAD_SAFETY_TEST_THREADS];

  // Set things up.
  KASSERT(vfs_mkdir("/thread_safety_test") == 0);
  KASSERT(vfs_mkdir("/thread_safety_test/a") == 0);
  KASSERT(vfs_mkdir("/thread_safety_test/a/b") == 0);

  thread_safety_test_t test;
  kmutex_init(&test.mu);
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    test.fds_open[i] = test.fds_total_count[i] = 0;
  }

  for (int i = 0; i < THREAD_SAFETY_TEST_THREADS; ++i) {
    KASSERT(kthread_create(&threads[i],
                           &vfs_open_thread_safety_test_func, &test) == 0);
    scheduler_make_runnable(threads[i]);
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

static void unlink_test() {
  KTEST_BEGIN("vfs_unlink(): basic test");
  int fd = vfs_open("/unlink", VFS_O_CREAT | VFS_O_RDWR);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("/unlink"));
  KEXPECT_EQ(-ENOENT, vfs_open("/unlink", VFS_O_RDWR));

  KTEST_BEGIN("vfs_unlink(): non-existent file");
  KEXPECT_EQ(-ENOENT, vfs_unlink("/doesnt_exist"));

  KTEST_BEGIN("vfs_unlink(): in a directory");
  vfs_mkdir("/unlink");
  vfs_mkdir("/unlink/a");
  fd = vfs_open("/unlink/a/file", VFS_O_CREAT | VFS_O_RDWR);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("/unlink/./a/../../unlink/a/./file"));
  KEXPECT_EQ(-ENOENT, vfs_unlink("/unlink/./a/../../unlink/a/./file"));

  KTEST_BEGIN("vfs_unlink(): non-directory in path");
  fd = vfs_open("/unlink/a/file", VFS_O_CREAT | VFS_O_RDWR);
  vfs_close(fd);
  KEXPECT_EQ(-ENOTDIR, vfs_unlink("/unlink/a/file/in_file"));
  KEXPECT_EQ(0, vfs_unlink("/unlink/a/file")); // Clean up.

  KTEST_BEGIN("vfs_unlink(): unlinking directory");
  KEXPECT_EQ(-EISDIR, vfs_unlink("/unlink/a"));

  // Clean up.
  vfs_rmdir("/unlink/a");
  vfs_rmdir("/unlink");
}

static void cwd_test() {
  const int kBufSize = 100;
  char  buf[kBufSize];

#define EXPECT_CWD(path) \
  KEXPECT_EQ(kstrlen(path), vfs_getcwd(buf, kBufSize)); \
  KEXPECT_STREQ((path), buf)

  vfs_mkdir("/cwd_test");
  vfs_mkdir("/cwd_test/a");
  create_file("/cwd_test/file");

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
  KEXPECT_EQ(-EINVAL, vfs_chdir(""));

  KTEST_BEGIN("vfs_getcwd(): bad arguments");
  KEXPECT_EQ(-EINVAL, vfs_getcwd(0x0, 5));
  KEXPECT_EQ(-EINVAL, vfs_getcwd(buf, -1));
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, 0));
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, 3));
  const int len = vfs_getcwd(buf, kBufSize);
  KEXPECT_EQ(-ERANGE, vfs_getcwd(buf, len));

  KTEST_BEGIN("vfs_open(): respects cwd");
  create_file("/cwd_test/cwd_open_file");
  vfs_chdir("/cwd_test");
  int fd = vfs_open("cwd_open_file", VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  if (fd >= 0) {
    vfs_close(fd);
  }

  KTEST_BEGIN("vfs_mkdir(): respects cwd");
  vfs_chdir("/cwd_test");
  vfs_mkdir("cwd_mkdir_dir");
  EXPECT_CAN_CREATE_FILE("/cwd_test/cwd_mkdir_dir/file");
  KEXPECT_EQ(0, vfs_rmdir("/cwd_test/cwd_mkdir_dir"));

  KTEST_BEGIN("vfs_rmdir(): respects cwd");
  vfs_chdir("/cwd_test");
  vfs_mkdir("/cwd_test/cwd_rmdir_dir");
  KEXPECT_EQ(0, vfs_rmdir("cwd_rmdir_dir"));

  KTEST_BEGIN("vfs_unlink(): respects cwd");
  vfs_chdir("/cwd_test");
  create_file("/cwd_test/cwd_unlink_file");
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

static void rw_test() {
  const char kFile[] = "/rw_test_file";
  const char kDir[] = "/rw_test_dir";
  const int kBufSize = 512;
  char buf[kBufSize];
  create_file(kFile);
  KEXPECT_EQ(0, vfs_mkdir(kDir));

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
  create_file(kFile);

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

static void write_large_test() {
  const char kFile[] = "/write_large_test";
  const int kBufSize = 4096;
  char* buf = (char*)kmalloc(kBufSize);
  char* buf_read = (char*)kmalloc(kBufSize);
  create_file(kFile);

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
  klogf("<wrote %d bytes in %d chunks>\n", kBufSize - bytes_left, write_chunks);

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
  klogf("<read %d bytes in %d chunks>\n", kBufSize - bytes_left, read_chunks);

  KEXPECT_EQ(0, kmemcmp(buf, buf_read, kBufSize));

  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(kFile));
  kfree(buf);
  kfree(buf_read);
}

// Multi-thread vfs_write() test.  Each thread repeatedly writes 'abc' and
// '1234' to a file descriptor, and at the end we verify that the writes didn't
// step on each other (i.e., each happened atomically).
#define WRITE_SAFETY_ITERS 10 * THREAD_SAFETY_MULTIPLIER
#define WRITE_SAFETY_THREADS 5
static void* write_thread_test_func(void* arg) {
  const int fd = (int)arg;
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

static void write_thread_test() {
  KTEST_BEGIN("vfs_write(): thread-safety test");
  kthread_t threads[WRITE_SAFETY_THREADS];

  create_file("/vfs_write_thread_safety_test");
  int fd = vfs_open("/vfs_write_thread_safety_test", VFS_O_RDWR);
  for (int i = 0; i < WRITE_SAFETY_THREADS; ++i) {
    KASSERT(kthread_create(&threads[i],
                           &write_thread_test_func, (void*)fd) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < WRITE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  // Make sure all the writes were atomic.
  vfs_close(fd);
  fd = vfs_open("/vfs_write_thread_safety_test", VFS_O_RDWR);
  char buf[512];
  int letters = 0, nums = 0;
  while (1) {
    int len = vfs_read(fd, buf, 3);
    if (len == 0) {
      break;
    }

    if (buf[0] == '1') {
      const int len2 = vfs_read(fd, &buf[3], 1);
      if (len2 != 1) {
        KEXPECT_EQ(1, len2);
      }
      len += len2;
    }
    buf[len] = '\0';

    if (buf[0] == 'a') {
      if (len != 3 || kstrncmp(buf, "abc", 3) != 0) {
        KEXPECT_EQ(3, len);
        KEXPECT_STREQ("abc", buf);
      }
      letters++;
    } else if (buf[0] == '1') {
      if (len != 4 || kstrncmp(buf, "1234", 4) != 0) {
        KEXPECT_EQ(4, len);
        KEXPECT_STREQ("1234", buf);
      }
      nums++;
    } else {
      // TODO(aoates): add a better way to expect this.
      KEXPECT_EQ(0, 1);
      break;
    }
  }
  vfs_close(fd);

  KEXPECT_EQ(WRITE_SAFETY_THREADS * WRITE_SAFETY_ITERS, letters);
  KEXPECT_EQ(WRITE_SAFETY_THREADS * WRITE_SAFETY_ITERS, nums);

  KEXPECT_EQ(0, vfs_unlink("/vfs_write_thread_safety_test"));
}

static void rw_mode_test() {
  const char kFile[] = "/rw_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];

  // Create a file and put some data in it.
  int fd = vfs_open(kFile, VFS_O_CREAT | VFS_O_RDWR);
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

// Run vfs_getdents() on the given fd and verify it matches the given set of
// dirents.
// TODO(aoates): actually verify the vnode numbers vfs_getdents returns.
typedef struct {
  int vnode;
  const char* name;
} edirent_t;
static void EXPECT_GETDENTS(int fd, int expected_num, edirent_t expected[]) {
  const int kBufSize = sizeof(dirent_t) * 3;  // Ensure we have several calls.
  char buf[kBufSize];
  int num_dirents = 0;

  while (1) {
    const int len = vfs_getdents(fd, (dirent_t*)(&buf[0]), kBufSize);
    if (len < 0) {
      KEXPECT_GE(len, -0);
      break;
    }
    if (len == 0) {
      break;
    }

    int buf_offset = 0;
    do {
      dirent_t* ent = (dirent_t*)(&buf[buf_offset]);
      num_dirents++;
      buf_offset += ent->length;

      klogf("dirent: %d -> %s\n", ent->vnode, ent->name);

      // Ignore the root lost+found and /dev directories.
      if (kstrcmp(ent->name, "lost+found") == 0 ||
          kstrcmp(ent->name, "dev") == 0) {
        num_dirents--;
        continue;
      }

      // Make sure the dirent matches one of the expected.
      int i;
      for (i = 0; i < expected_num; ++i) {
        if (kstrcmp(ent->name, expected[i].name) == 0) {
          break;
        }
      }
      if (i == expected_num) {
        klogf("Error: dirent <%d, %s> doesn't match any expected dirents\n",
              ent->vnode, ent->name);
        KEXPECT_EQ(0, 1); // TODO(aoates): more elegant way to signal this
      }
    } while (buf_offset < len);
  }

  KEXPECT_EQ(expected_num, num_dirents);
}

static void getdents_test() {
  edirent_t root_expected[] = {{0, "."}, {0, ".."}};
  edirent_t getdents_expected[] = {
    {-1, "."}, {0, ".."}, {-1, "a"}, {-1, "b"}, {-1, "c"},
    {-1, "f1"}, {-1, "f2"}};
  edirent_t getdents_a_expected[] = {
    {-1, "."}, {0, ".."}, {-1, "1"}, {-1, "f3"}};

  KTEST_BEGIN("vfs_getdents(): root");
  int fd = vfs_open("/", VFS_O_RDONLY);
  EXPECT_GETDENTS(fd, 2, root_expected);
  vfs_close(fd);

  vfs_mkdir("/getdents");
  vfs_mkdir("/getdents/a");
  vfs_mkdir("/getdents/b");
  vfs_mkdir("/getdents/c");
  vfs_mkdir("/getdents/a/1");
  create_file("/getdents/f1");
  create_file("/getdents/f2");
  create_file("/getdents/a/f3");

  KTEST_BEGIN("vfs_getdents(): files and directories");
  fd = vfs_open("/", VFS_O_RDONLY);
  EXPECT_GETDENTS(fd, 3, (edirent_t[]){{0, "."}, {0, ".."}, {-1, "getdents"}});
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): subdir #2");
  fd = vfs_open("/getdents", VFS_O_RDONLY);
  EXPECT_GETDENTS(fd, 7, getdents_expected);
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): subdir #3");
  fd = vfs_open("/getdents/a", VFS_O_RDONLY);
  EXPECT_GETDENTS(fd, 4, getdents_a_expected);
  vfs_close(fd);

  KTEST_BEGIN("vfs_getdents(): cwd");
  vfs_chdir("/getdents");
  fd = vfs_open(".", VFS_O_RDONLY);
  EXPECT_GETDENTS(fd, 7, getdents_expected);
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

static void seek_test() {
  const char kFile[] = "/seek_test_file";
  const int kBufSize = 512;
  char buf[kBufSize];
  kmemset(buf, 0, kBufSize);
  create_file_with_data(kFile, "abcdefghijklmnopqrstuvwxyz");

  int fd = vfs_open(kFile, VFS_O_RDWR);
  KTEST_BEGIN("vfs_seek(): read");
  KEXPECT_EQ(0, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "defg", 4));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "hijk", 4));

  KTEST_BEGIN("vfs_seek(): write");
  KEXPECT_EQ(0, vfs_seek(fd, 5, VFS_SEEK_SET));
  KEXPECT_EQ(2, vfs_write(fd, "12", 2));
  KEXPECT_EQ(2, vfs_write(fd, "34", 2));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(26, vfs_read(fd, buf, kBufSize));
  KEXPECT_STREQ("abcde1234jklmnopqrstuvwxyz", buf);

  KTEST_BEGIN("vfs_seek(): SEEK_CUR");
  KEXPECT_EQ(0, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(0, vfs_seek(fd, 2, VFS_SEEK_CUR));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "1234", 4));

  KTEST_BEGIN("vfs_seek(): SEEK_END");
  KEXPECT_EQ(0, vfs_seek(fd, 3, VFS_SEEK_END));
  KEXPECT_EQ(2, vfs_write(fd, "12", 2));
  KEXPECT_EQ(2, vfs_write(fd, "34", 2));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(33, vfs_read(fd, buf, kBufSize));
  KEXPECT_EQ(0, kmemcmp("abcde1234jklmnopqrstuvwxyz\0\0\0" "1234", buf, 33));

  KTEST_BEGIN("vfs_seek(): negative seek");
  KEXPECT_EQ(0, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(0, vfs_seek(fd, -2, VFS_SEEK_CUR));
  KEXPECT_EQ(4, vfs_read(fd, buf, 4));
  KEXPECT_EQ(0, kstrncmp(buf, "bcde", 4));

  // TODO(aoates): negative seek from end.

  KTEST_BEGIN("vfs_seek(): negative seek");
  KEXPECT_EQ(0, vfs_seek(fd, 3, VFS_SEEK_SET));
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, -4, VFS_SEEK_CUR));
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, -1, VFS_SEEK_SET));

  KTEST_BEGIN("vfs_seek(): seek not shared across independent FDs");
  int fd1 = vfs_open(kFile, VFS_O_RDONLY);
  int fd2 = vfs_open(kFile, VFS_O_RDONLY);
  KEXPECT_EQ(0, vfs_seek(fd1, 3, VFS_SEEK_SET));
  KEXPECT_EQ(0, vfs_seek(fd2, 10, VFS_SEEK_SET));
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
  // seek is not shared across non-dup()'d fds

  // Clean up.
  vfs_close(fd);
  vfs_unlink(kFile);
}

#define BAD_INODE_SAFETY_ITERS 10 * THREAD_SAFETY_MULTIPLIER
#define BAD_INODE_SAFETY_THREADS 5
static void* bad_inode_thread_test_func(void* arg) {
  for (int i = 0; i < BAD_INODE_SAFETY_ITERS; ++i) {
    vnode_t* node = vfs_get(vfs_get_root_fs(), 52187 + (i % 3));
    KEXPECT_EQ(0x0, (int)node);
  }
  return 0x0;
}

static void bad_inode_thread_test() {
  KTEST_BEGIN("vfs_get(): bad inode thread-safety test");
  kthread_t threads[BAD_INODE_SAFETY_THREADS];

  for (int i = 0; i < BAD_INODE_SAFETY_THREADS; ++i) {
    KASSERT(kthread_create(&threads[i], &bad_inode_thread_test_func, 0x0) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < BAD_INODE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  vfs_log_cache();
}

static void get_bad_inode_test() {
  KTEST_BEGIN("vfs_get(): bad inode");
  vnode_t* node = vfs_get(vfs_get_root_fs(), 52187);
  KEXPECT_EQ(0x0, (int)node);

  bad_inode_thread_test();

  // TODO(aoates): test vfs_open, cwd, etc handle dangling inodes
}

void reverse_path_test() {
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
#define CREATE_SAFETY_ITERS 10 * THREAD_SAFETY_MULTIPLIER
#define CREATE_SAFETY_THREADS 5
static void* create_thread_test_func(void* arg) {
  const char kTestDir[] = "/create_thread_test";
  const int thread_num = (int)arg;
  for (int i = 0; i < CREATE_SAFETY_ITERS; ++i) {
    char buf[512];
    ksprintf(buf, "%s/%d.%d", kTestDir, thread_num, i);
    int fd = vfs_open(buf, VFS_O_CREAT | VFS_O_RDWR);
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
  const int thread_num = (int)arg;
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

static void create_thread_test() {
  KTEST_BEGIN("vfs_open(VFS_O_CREAT): thread-safety test");
  const char kTestDir[] = "/create_thread_test";
  kthread_t threads[CREATE_SAFETY_THREADS];

  KEXPECT_EQ(0, vfs_mkdir(kTestDir));
  for (int i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    KASSERT(
        kthread_create(&threads[i], &create_thread_test_func, (void*)i) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  // Make sure they're all created correctly.
  const int kNumExpected = CREATE_SAFETY_ITERS * CREATE_SAFETY_THREADS + 2;
  char expected_names[kNumExpected][30];
  edirent_t expected_dirents[kNumExpected];
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
    EXPECT_GETDENTS(fd, kNumExpected, expected_dirents);
    vfs_close(fd);
  }

  KTEST_BEGIN("vfs_unlink(): thread-safety test");
  for (int i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    KASSERT(
        kthread_create(&threads[i], &unlink_thread_test_func, (void*)i) == 0);
    scheduler_make_runnable(threads[i]);
  }

  for (int i = 0; i < CREATE_SAFETY_THREADS; ++i) {
    kthread_join(threads[i]);
  }

  fd = vfs_open(kTestDir, VFS_O_RDONLY);
  if (fd >= 0) {
    EXPECT_GETDENTS(fd, 2, expected_dirents);
    vfs_close(fd);
  }

  KEXPECT_EQ(0, vfs_rmdir(kTestDir));
}

// Test that if we create a file, then unlink it before closing it, we can still
// read from it.
static void unlink_open_file_test() {
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
static void unlink_open_directory_test() {
  KTEST_BEGIN("rmdir() open directory test");
  const char kDir[] = "unlink_open_directory_test";
  KEXPECT_EQ(0, vfs_mkdir(kDir));

  const int fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_rmdir(kDir));

  // The file should not be in the directory any more.
  EXPECT_FILE_DOESNT_EXIST(kDir);

  EXPECT_GETDENTS(fd, 0, 0x0);

  KEXPECT_EQ(0, vfs_close(fd));
  EXPECT_FILE_DOESNT_EXIST(kDir);
}

// Test trying to create a file in an unlinked directory (that's still open for
// reading).
static void create_in_unlinked_directory() {
  KTEST_BEGIN("create in rmdir()'d directory test");
  const char kDir[] = "create_in_unlinked_directory_test";
  const char kFile[] = "create_in_unlinked_directory_test/file";
  KEXPECT_EQ(0, vfs_mkdir(kDir));

  const int fd = vfs_open(kDir, VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_rmdir(kDir));

  // Try to create a file in the directory.  It should fail.
  const int fd2 = vfs_open(kFile, VFS_O_RDWR | VFS_O_CREAT);
  KEXPECT_EQ(-ENOENT, fd2);

  EXPECT_GETDENTS(fd, 0, 0x0);

  KEXPECT_EQ(0, vfs_close(fd));
}

// Create a file, write a pattern of N bytes to it, then verify that we can see
// it via read_page.
static void read_page_test(const char* filename, const int size) {
  const uint32_t page_buf_phys = page_frame_alloc();
  void* const page_buf = (void*)phys2virt(page_buf_phys);

  int fd = vfs_open(filename, VFS_O_RDWR | VFS_O_CREAT);
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

  // Read the page and make sure it matches.
  kmemset(page_buf, 0, PAGE_SIZE);
  memobj->ops->read_page(memobj, kPrefixPages, page_buf);
  KEXPECT_EQ(0, kmemcmp(page_buf, buf, size));
  for (int i = size; i < PAGE_SIZE; ++i) {
    uint8_t bufval = ((uint8_t*)page_buf)[i];
    if (bufval != 0) KEXPECT_EQ(0, bufval);
  }

  KEXPECT_EQ(0, vfs_close(fd));
  KEXPECT_EQ(0, vfs_unlink(filename));
  page_frame_free(page_buf_phys);
}

// Test a vnode-backed memobj.
static void memobj_test() {
  KTEST_BEGIN("vfs_get_memobj() test");
  const char kDir[] = "memobj_test";
  KEXPECT_EQ(0, vfs_mkdir(kDir));

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
  int fd = vfs_open(kFile, VFS_O_RDONLY | VFS_O_CREAT);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDONLY, &unused_memobj));
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_WRONLY, &unused_memobj));
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_RDWR, &unused_memobj));
  KEXPECT_EQ(0, vfs_close(fd));

  fd = vfs_open(kFile, VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_RDONLY, &unused_memobj));
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_WRONLY, &unused_memobj));
  KEXPECT_EQ(-EACCES, vfs_get_memobj(fd, VFS_O_RDWR, &unused_memobj));
  KEXPECT_EQ(0, vfs_close(fd));

  fd = vfs_open(kFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDONLY, &unused_memobj));
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_WRONLY, &unused_memobj));
  KEXPECT_EQ(0, vfs_get_memobj(fd, VFS_O_RDWR, &unused_memobj));
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

static void mknod_test() {
  const char kDir[] = "mknod_test_dir";
  const char kRegFile[] = "mknod_test_dir/reg";
  const char kCharDevFile[] = "mknod_test_dir/char";
  const char kBlockDevFile[] = "mknod_test_dir/block";

  KEXPECT_EQ(0, vfs_mkdir(kDir));

  KTEST_BEGIN("mknod(): regular file test");
  KEXPECT_EQ(0, vfs_mknod(kRegFile, VFS_S_IFREG, mkdev(0, 0)));

  int fd = vfs_open(kRegFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(5, vfs_write(fd, "abcde", 5));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  char buf[10];
  KEXPECT_EQ(5, vfs_read(fd, buf, 10));
  KEXPECT_EQ(0, kmemcmp("abcde", buf, 5));
  vfs_close(fd);

  KTEST_BEGIN("mknod(): empty path test");
  KEXPECT_EQ(-EINVAL, vfs_mknod("", VFS_S_IFREG, mkdev(0, 0)));

  KTEST_BEGIN("mknod(): existing file test");
  KEXPECT_EQ(-EEXIST, vfs_mknod(kRegFile, VFS_S_IFREG, mkdev(0, 0)));

  KTEST_BEGIN("mknod(): bath path test");
  KEXPECT_EQ(-ENOENT, vfs_mknod("bad/path/test", VFS_S_IFREG, mkdev(0, 0)));

  KTEST_BEGIN("mknod(): character device file test");
  KEXPECT_EQ(0, vfs_mknod(kCharDevFile, VFS_S_IFCHR, mkdev(0, 0)));

  fd = vfs_open(kCharDevFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  KTEST_BEGIN("mknod(): block device file test");
  KEXPECT_EQ(0, vfs_mknod(kBlockDevFile, VFS_S_IFBLK, mkdev(0, 0)));

  fd = vfs_open(kBlockDevFile, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);

  // TODO(aoates): test character device functionality.

  vfs_unlink(kBlockDevFile);
  vfs_unlink(kCharDevFile);
  vfs_unlink(kRegFile);
  vfs_rmdir(kDir);
}

static void block_device_test() {
  const char kDir[] = "block_dev_test_dir";
  const char kBlockDevFile[] = "block_dev_test_dir/block";
  const int kRamdiskSize = PAGE_SIZE * 3;

  KEXPECT_EQ(0, vfs_mkdir(kDir));

  // Create a ramdisk for the test.
  ramdisk_t* ramdisk = 0x0;
  block_dev_t ramdisk_bd;
  KASSERT(ramdisk_create(kRamdiskSize, &ramdisk) == 0);
  ramdisk_set_blocking(ramdisk, 1, 1);
  ramdisk_dev(ramdisk, &ramdisk_bd);

  apos_dev_t dev = mkdev(DEVICE_MAJOR_RAMDISK, DEVICE_ID_UNKNOWN);
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
    KEXPECT_EQ(kBufSize, ramdisk_bd.write(&ramdisk_bd, i, buf, kBufSize));
  }

  KTEST_BEGIN("vfs_read(): block device");
  kstrcpy(buf, "ramdisk");
  KEXPECT_EQ(kBufSize, ramdisk_bd.write(&ramdisk_bd, 0, buf, kBufSize));
  kmemset(buf, 0, kBufSize);
  KEXPECT_EQ(10, vfs_read(fd, buf, 10));
  KEXPECT_EQ(0, kmemcmp("ramdisk\0\0\0", buf, 10));

  KTEST_BEGIN("vfs_write(): block device");
  KEXPECT_EQ(7, vfs_write(fd, "written", 7));
  KEXPECT_EQ(kBufSize, ramdisk_bd.read(&ramdisk_bd, 0, buf, kBufSize));
  KEXPECT_EQ(0, kmemcmp("ramdisk\0\0\0written\0\0\0", buf, 20));

  KTEST_BEGIN("vfs_seek(): block device: seek within block");
  KEXPECT_EQ(0, vfs_seek(fd, kBufSize * 2 + 5, VFS_SEEK_SET));
  KEXPECT_EQ(6, vfs_write(fd, "write2", 6));
  KEXPECT_EQ(kBufSize, ramdisk_bd.read(&ramdisk_bd, 2, buf, kBufSize));
  KEXPECT_EQ(0, kmemcmp("\0\0\0\0\0write2\0\0\0\0", buf, 15));

  KTEST_BEGIN("vfs_seek(): block device: seek past end of device");
  KEXPECT_EQ(-EINVAL, vfs_seek(fd, kBufSize * 30, VFS_SEEK_SET));

  vfs_close(fd);

  // Cleanup.
  // TODO(aoates): make this work
  block_cache_clear_unpinned();  // Make sure all entries for dev are flushed.
  KASSERT(dev_unregister_block(dev) == 0);
  ramdisk_destroy(ramdisk);

  vfs_unlink(kBlockDevFile);
  vfs_rmdir(kDir);
}

// TODO(aoates): multi-threaded test for creating a file in directory that is
// being unlinked.  There may currently be a race condition where a new entry is
// creating while the directory is being deleted.

void vfs_test() {
  KTEST_SUITE_BEGIN("vfs test");

  if (kstrcmp(vfs_get_root_fs()->fstype, "ramfs") == 0) {
    ramfs_enable_blocking(vfs_get_root_fs());
  }

  open_test();
  mkdir_test();
  file_table_reclaim_test();
  vfs_open_thread_safety_test();
  unlink_test();
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
  block_device_test();

  reverse_path_test();

  if (kstrcmp(vfs_get_root_fs()->fstype, "ramfs") == 0) {
    ramfs_disable_blocking(vfs_get_root_fs());
  }
}
