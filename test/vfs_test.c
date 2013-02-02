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

// Helper method to create a file for a test.
static void create_file(const char* path) {
  const int fd = vfs_open(path, VFS_O_CREAT | VFS_O_RDWR);
  KASSERT(fd >= 0);
  vfs_close(fd);
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
  vfs_unlink("/cwd_test/file");
  vfs_rmdir("/cwd_test/a");
  vfs_rmdir("/cwd_test");
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
                           &write_thread_test_func, (void*)fd));
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
  cwd_test();
  rw_test();
  write_thread_test();
  rw_mode_test();

  reverse_path_test();

  ramfs_disable_blocking(vfs_get_root_fs());
}
