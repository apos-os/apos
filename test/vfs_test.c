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

// Test that we correctly refcount parent directories when calling vfs_open().
static void open_parent_refcount_test() {
  KTEST_BEGIN("vfs_open(): parent refcount test");
  KEXPECT_EQ(0, vfs_mkdir("/ref_dir1"));
  KEXPECT_EQ(0, vfs_mkdir("/ref_dir1/dir2"));

  const int fd1 = vfs_open("/ref_dir1/dir2/test1", VFS_O_CREAT);
  KEXPECT_GE(fd1, 0);

  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(1, "/ref_dir1/dir2/test1");

  const int fd2 = vfs_open("/ref_dir1/dir2/test1", VFS_O_CREAT);
  KEXPECT_GE(fd2, 0);

  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(2, "/ref_dir1/dir2/test1");

  KEXPECT_EQ(0, vfs_close(fd1));
  KEXPECT_EQ(0, vfs_close(fd2));

  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2");
  EXPECT_VNODE_REFCOUNT(0, "/ref_dir1/dir2/test1");

  // Clean up.
  // TODO(aoates): remove test1 file and directories.
}

// Test calling vfs_open() on a directory.
static void open_dir_test() {
  KTEST_BEGIN("vfs_open(): on directory test");
  KEXPECT_EQ(0, vfs_mkdir("/dir1"));
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  // Try to vfs_open() the directory.
  KEXPECT_EQ(-EISDIR, vfs_open("/dir1", 0));
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  // Clean up.
  KEXPECT_EQ(0, vfs_rmdir("/dir1"));
}

static void open_test() {
  KTEST_BEGIN("vfs_open() test");

  vfs_log_cache();
  KEXPECT_EQ(-ENOENT, vfs_open("/test1", 0));
  EXPECT_VNODE_REFCOUNT(-ENOENT, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(0, vfs_open("/test1", VFS_O_CREAT));
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(1, vfs_open("/test1", VFS_O_CREAT));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  vfs_log_cache();

  KEXPECT_EQ(2, vfs_open("/test2", VFS_O_CREAT));
  EXPECT_VNODE_REFCOUNT(2, "/test1");
  EXPECT_VNODE_REFCOUNT(1, "/test2");
  vfs_log_cache();

  KEXPECT_EQ(3, vfs_open("/test1", 0));
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
  KEXPECT_EQ(1, vfs_open("/test3", VFS_O_CREAT));
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
  KEXPECT_EQ(0, vfs_open("/test1", 0));
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  vfs_log_cache();

  // Close everything.
  KEXPECT_EQ(0, vfs_close(0));
  KEXPECT_EQ(0, vfs_close(1));

  // TODO(aoates): test in subdirectories once mkdir works
  KTEST_BEGIN("vfs_open() w/ directories test");
  KEXPECT_EQ(-EISDIR, vfs_open("/", 0));
  EXPECT_VNODE_REFCOUNT(0, "/");
  KEXPECT_EQ(-ENOTDIR, vfs_open("/test1/test2", 0));
  EXPECT_VNODE_REFCOUNT(0, "/");
  KEXPECT_EQ(-ENOTDIR, vfs_open("/test1/test2", VFS_O_CREAT));
  EXPECT_VNODE_REFCOUNT(0, "/");

  open_parent_refcount_test();
  open_dir_test();
}

static void mkdir_test() {
  KTEST_BEGIN("vfs_mkdir() test");

  // Make sure we have some normal files around.
  const int test1_fd = vfs_open("/test1", VFS_O_CREAT);
  KEXPECT_GE(test1_fd, 0);

  KEXPECT_EQ(-EEXIST, vfs_mkdir("/"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/test1"));
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");

  KEXPECT_EQ(-ENOTDIR, vfs_mkdir("/test1/dir1"));
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");

  KTEST_BEGIN("regular mkdir()");
  KEXPECT_EQ(0, vfs_mkdir("/dir1"));
  KEXPECT_EQ(0, vfs_mkdir("/dir2"));
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir1"));
  KEXPECT_EQ(-EEXIST, vfs_mkdir("/dir2"));
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KTEST_BEGIN("nested mkdir()");
  KEXPECT_EQ(-ENOENT, vfs_mkdir("/dir1/dir1a/dir1b"));
  KEXPECT_EQ(0, vfs_mkdir("/dir1/dir1a"));
  KEXPECT_EQ(0, vfs_mkdir("/dir1/dir1a/dir1b"));
  EXPECT_VNODE_REFCOUNT(0, "/");
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
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");

  KTEST_BEGIN("rmdir(): not a directory");
  KEXPECT_EQ(-ENOTDIR, vfs_rmdir("/test1"));
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(1, "/test1");
  // TODO(aoates): test nested not-a-dir

  KTEST_BEGIN("rmdir(): root directory");
  KEXPECT_EQ(-EPERM, vfs_rmdir("/"));
  EXPECT_VNODE_REFCOUNT(0, "/");

  KTEST_BEGIN("rmdir(): invalid paths");
  KEXPECT_EQ(-EINVAL, vfs_rmdir("/dir1/dir1a/."));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/dir1a/dir1b/.."));
  EXPECT_VNODE_REFCOUNT(0, "/");
  EXPECT_VNODE_REFCOUNT(0, "/dir1");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a");
  EXPECT_VNODE_REFCOUNT(0, "/dir1/dir1a/dir1b");

  KTEST_BEGIN("rmdir(): not empty");
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/"));
  KEXPECT_EQ(-ENOTEMPTY, vfs_rmdir("/dir1/dir1a"));
  EXPECT_VNODE_REFCOUNT(0, "/");
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
    const int fd = vfs_open(kTestFile, VFS_O_CREAT);
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
                      VFS_O_CREAT);
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
                           &vfs_open_thread_safety_test_func, &test));
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

  // TODO(aoates): clean up
}

void unlink_test() {
  KTEST_BEGIN("vfs_unlink(): basic test");
  int fd = vfs_open("/unlink", VFS_O_CREAT);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("/unlink"));
  KEXPECT_EQ(-ENOENT, vfs_open("/unlink", 0));

  KTEST_BEGIN("vfs_unlink(): non-existent file");
  KEXPECT_EQ(-ENOENT, vfs_unlink("/doesnt_exist"));

  KTEST_BEGIN("vfs_unlink(): in a directory");
  vfs_mkdir("/unlink");
  vfs_mkdir("/unlink/a");
  fd = vfs_open("/unlink/a/file", VFS_O_CREAT);
  vfs_close(fd);
  KEXPECT_EQ(0, vfs_unlink("/unlink/./a/../../unlink/a/./file"));
  KEXPECT_EQ(-ENOENT, vfs_unlink("/unlink/./a/../../unlink/a/./file"));

  KTEST_BEGIN("vfs_unlink(): non-directory in path");
  fd = vfs_open("/unlink/a/file", VFS_O_CREAT);
  vfs_close(fd);
  KEXPECT_EQ(-ENOTDIR, vfs_unlink("/unlink/a/file/in_file"));
  KEXPECT_EQ(0, vfs_unlink("/unlink/a/file")); // Clean up.

  KTEST_BEGIN("vfs_unlink(): unlinking directory");
  KEXPECT_EQ(-EISDIR, vfs_unlink("/unlink/a"));

  // Clean up.
  vfs_rmdir("/unlink/a");
  vfs_rmdir("/unlink");
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

void vfs_test() {
  KTEST_SUITE_BEGIN("vfs test");

  ramfs_enable_blocking(vfs_get_root_fs());

  open_test();
  mkdir_test();
  file_table_reclaim_test();
  vfs_open_thread_safety_test();
  unlink_test();
  reverse_path_test();

  ramfs_disable_blocking(vfs_get_root_fs());
}
