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

#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "vfs/fifo.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

// Tests:
//  - symlink to FIFO
//  - read/write
//  - interrupt open, read, and write
//  - filesystem permissions
//  - invalid arguments

static void mknod_test(void) {
  KTEST_BEGIN("mknod() FIFO test");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));


  KTEST_BEGIN("mknod() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

static void* do_open(void* arg) {
  int mode = (int)arg;
  int result = vfs_open("fifo_test/fifo", mode);
  return (void*)result;
}

static void stat_test(void) {
  KTEST_BEGIN("stat() FIFO test");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat("fifo_test/fifo", &stat));
  KEXPECT_EQ(VFS_S_IFIFO | VFS_S_IRWXU, stat.st_mode);
  KEXPECT_EQ(1, VFS_S_ISFIFO(stat.st_mode));
  KEXPECT_GE(stat.st_ino, 0);
  KEXPECT_EQ(stat.st_nlink, 1);
  KEXPECT_EQ(0, stat.st_size);

  // TODO(aoates): test atim, mtim, ctim

  KEXPECT_LE(stat.st_blocks, 1);


  KTEST_BEGIN("lstat() FIFO test");
  apos_stat_t orig_stat = stat;
  KEXPECT_EQ(0, vfs_lstat("fifo_test/fifo", &stat));
  KEXPECT_EQ(0, kmemcmp(&stat, &orig_stat, sizeof(apos_stat_t)));


  KTEST_BEGIN("fstat() FIFO test");
  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &do_open, (void*)VFS_O_WRONLY));
  scheduler_make_runnable(thread);

  int fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(0, kmemcmp(&stat, &orig_stat, sizeof(apos_stat_t)));
  if (0 != kmemcmp(&stat, &orig_stat, sizeof(apos_stat_t)))
    klog("break");

  KEXPECT_EQ(0, vfs_close(fd));
  fd = (int)kthread_join(thread);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("stat() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

static void open_test(void) {
  KTEST_BEGIN("open() FIFO test (O_RDONLY)");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &do_open, (void*)VFS_O_WRONLY));
  scheduler_make_runnable(thread);

  int fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));
  fd = (int)kthread_join(thread);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("open() FIFO test (O_WRONLY)");

  KEXPECT_EQ(0, kthread_create(&thread, &do_open, (void*)VFS_O_RDONLY));
  scheduler_make_runnable(thread);

  fd = vfs_open("fifo_test/fifo", VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));
  fd = (int)kthread_join(thread);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("open() FIFO test (O_RDWR)");
  KEXPECT_EQ(-EINVAL, vfs_open("fifo_test/fifo", VFS_O_RDWR));

  KTEST_BEGIN("open() test cleanup");
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

typedef struct {
  int fd;
  bool started;
  bool finished;
  bool is_read;
} args_t;

static void* do_op(void* args) {
  args_t* op = (args_t*)args;
  op->started = true;
  op->finished = false;
  char buf[APOS_FIFO_BUF_SIZE + 5];
  int result;
  if (op->is_read)
    result = vfs_read(op->fd, buf, 50);
  else
    result = vfs_write(op->fd, buf, APOS_FIFO_BUF_SIZE + 5);
  op->finished = true;
  return (void*)result;
}

static void read_write_test(void) {
  KTEST_BEGIN("read() and write() FIFO basic test");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &do_open, (void*)VFS_O_WRONLY));
  scheduler_make_runnable(thread);

  int read_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY);
  KEXPECT_GE(read_fd, 0);
  int write_fd = (int)kthread_join(thread);
  KEXPECT_GE(write_fd, 0);

  KEXPECT_EQ(5, vfs_write(write_fd, "abcde", 5));

  char buf[100];
  KEXPECT_EQ(5, vfs_read(read_fd, buf, 5));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  KTEST_BEGIN("read() on write-only FIFO");
  KEXPECT_EQ(-EBADF, vfs_read(write_fd, buf, 5));

  KTEST_BEGIN("write() on read-only FIFO");
  KEXPECT_EQ(-EBADF, vfs_write(read_fd, buf, 5));


  KTEST_BEGIN("read() blocks on empty FIFO");
  args_t op;
  op.fd = read_fd;
  op.finished = op.started = false;
  op.is_read = true;

  KEXPECT_EQ(0, kthread_create(&thread, &do_op, &op));
  scheduler_make_runnable(thread);

  for (int i = 0; i < 10 && !op.started; ++i) scheduler_yield();

  KEXPECT_EQ(true, op.started);
  KEXPECT_EQ(false, op.finished);

  KEXPECT_EQ(5, vfs_write(write_fd, "12345", 5));

  for (int i = 0; i < 10 && !op.finished; ++i) scheduler_yield();
  KEXPECT_EQ(true, op.finished);
  KEXPECT_EQ(5, (int)kthread_join(thread));


  KTEST_BEGIN("write() blocks on full FIFO");
  op.fd = write_fd;
  op.finished = op.started = false;
  op.is_read = false;

  KEXPECT_EQ(0, kthread_create(&thread, &do_op, &op));
  scheduler_make_runnable(thread);

  for (int i = 0; i < 10 && !op.started; ++i) scheduler_yield();

  KEXPECT_EQ(true, op.started);
  KEXPECT_EQ(false, op.finished);

  KEXPECT_EQ(10, vfs_read(read_fd, buf, 10));

  for (int i = 0; i < 10 && !op.finished; ++i) scheduler_yield();
  KEXPECT_EQ(true, op.finished);
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE + 5, (int)kthread_join(thread));


  KTEST_BEGIN("seek() on FIFO test");
  KEXPECT_EQ(-ESPIPE, vfs_seek(read_fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(-ESPIPE, vfs_seek(write_fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(-ESPIPE, vfs_seek(read_fd, 50, VFS_SEEK_SET));
  KEXPECT_EQ(-ESPIPE, vfs_seek(write_fd, 50, VFS_SEEK_SET));


  KTEST_BEGIN("read()/write() test cleanup");
  KEXPECT_EQ(0, vfs_close(read_fd));
  KEXPECT_EQ(0, vfs_close(write_fd));

  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

void vfs_fifo_test(void) {
  KTEST_SUITE_BEGIN("VFS FIFO test");
  const int initial_cache_size = vfs_cache_size();

  mknod_test();
  stat_test();
  open_test();
  read_write_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
