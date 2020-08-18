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

#include "memory/kmalloc.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/limit.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/wait.h"
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
  int mode = (intptr_t)arg;
  intptr_t result = vfs_open("fifo_test/fifo", mode);
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
  fd = (intptr_t)kthread_join(thread);
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
  fd = (intptr_t)kthread_join(thread);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("open() FIFO test (O_WRONLY)");

  KEXPECT_EQ(0, kthread_create(&thread, &do_open, (void*)VFS_O_RDONLY));
  scheduler_make_runnable(thread);

  fd = vfs_open("fifo_test/fifo", VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));
  fd = (intptr_t)kthread_join(thread);
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
  intptr_t result;
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
  int write_fd = (intptr_t)kthread_join(thread);
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
  KEXPECT_EQ(5, (intptr_t)kthread_join(thread));


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
  KEXPECT_EQ(APOS_FIFO_BUF_SIZE + 5, (intptr_t)kthread_join(thread));


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

static void interrupt_handler(int sig) {}

static void setup_interrupt(void) {
  struct ksigaction act;
  act.sa_handler = &interrupt_handler;
  act.sa_flags = 0;
  ksigemptyset(&act.sa_mask);
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &act, NULL));
}

static void do_open_proc(void* arg) {
  setup_interrupt();
  *(bool*)arg = true;
  proc_exit(vfs_open("fifo_test/fifo", VFS_O_RDONLY));
}

static void do_read_proc(void* arg) {
  setup_interrupt();

  char buf[20];
  int fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY);
  *(bool*)arg = true;
  proc_exit(vfs_read(fd, buf, 5));
}

static void do_write_proc(void* arg) {
  setup_interrupt();

  void* buf = kmalloc(APOS_FIFO_BUF_SIZE);
  int fd = vfs_open("fifo_test/fifo", VFS_O_WRONLY);
  vfs_write(fd, buf, APOS_FIFO_BUF_SIZE);
  *(bool*)arg = true;
  int result = vfs_write(fd, "toomuch", 7);
  kfree(buf);
  proc_exit(result);
}

static void interrupt_test(void) {
  KTEST_BEGIN("read() and write() FIFO basic test");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));


  KTEST_BEGIN("open() on FIFO interrupted");
  bool flag = false;
  pid_t child = proc_fork(do_open_proc, &flag);
  KEXPECT_GE(child, 0);

  for (int i = 0; i < 10 && !flag; ++i) scheduler_yield();
  KEXPECT_EQ(true, flag);
  KEXPECT_EQ(0, proc_force_signal(proc_get(child), SIGUSR1));
  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(status, -EINTR);


  KTEST_BEGIN("read() on FIFO interrupted");
  flag = false;
  child = proc_fork(do_read_proc, &flag);
  KEXPECT_GE(child, 0);

  int fd = vfs_open("fifo_test/fifo", VFS_O_WRONLY);
  KEXPECT_GE(fd, 0);
  for (int i = 0; i < 10 && !flag; ++i) scheduler_yield();
  KEXPECT_EQ(true, flag);
  KEXPECT_EQ(0, proc_force_signal(proc_get(child), SIGUSR1));
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(status, -EINTR);
  vfs_close(fd);


  KTEST_BEGIN("write() on FIFO interrupted");
  flag = false;
  child = proc_fork(do_write_proc, &flag);
  KEXPECT_GE(child, 0);

  fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);
  for (int i = 0; i < 10 && !flag; ++i) scheduler_yield();
  KEXPECT_EQ(true, flag);
  KEXPECT_EQ(0, proc_force_signal(proc_get(child), SIGUSR1));
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(status, -EINTR);
  vfs_close(fd);


  KTEST_BEGIN("FIFO interrupt test cleanup");
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

static void nonblock_test(void) {
  KTEST_BEGIN("FIFO: open(O_NONBLOCK | O_RDONLY) without writers");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  int fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(fd, 0);
  vfs_close(fd);


  KTEST_BEGIN("FIFO: open(O_NONBLOCK | O_WRONLY) without readers");
  KEXPECT_EQ(-ENXIO, vfs_open("fifo_test/fifo", VFS_O_WRONLY | VFS_O_NONBLOCK));


  KTEST_BEGIN("FIFO: open(O_NONBLOCK) with readers and writers");
  fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  int fd2 = vfs_open("fifo_test/fifo", VFS_O_WRONLY | VFS_O_NONBLOCK);
  int fd3 = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(fd, 0);
  KEXPECT_GE(fd2, 0);
  KEXPECT_GE(fd3, 0);

  vfs_close(fd);
  vfs_close(fd2);
  vfs_close(fd3);


  KTEST_BEGIN("FIFO: read() with no writers (non-block)");
  int rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  char buf[10];
  KEXPECT_EQ(0, vfs_read(rd_fd, buf, 10));


  KTEST_BEGIN("FIFO: read() with writer but no data (non-block)");
  int wr_fd = vfs_open("fifo_test/fifo", VFS_O_WRONLY | VFS_O_NONBLOCK);
  KEXPECT_EQ(-EAGAIN, vfs_read(rd_fd, buf, 10));


  KTEST_BEGIN("FIFO: read() with writer and data (non-block)");
  KEXPECT_EQ(5, vfs_write(wr_fd, "abcde", 5));
  KEXPECT_EQ(5, vfs_read(rd_fd, buf, 10));


  KTEST_BEGIN("FIFO: write() with no readers (non-block)");
  vfs_close(rd_fd);
  KEXPECT_EQ(-EPIPE, vfs_write(wr_fd, "abcde", 5));
  proc_suppress_signal(proc_current(), SIGPIPE);


  KTEST_BEGIN("FIFO: write() with reader (non-block)");
  rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_EQ(5, vfs_write(wr_fd, "abcde", 5));


  KTEST_BEGIN("FIFO: write() with reader; FIFO full (non-block)");
  char* big_buf = kmalloc(5000);
  KEXPECT_LT(0, vfs_write(wr_fd, big_buf, 5000));
  KEXPECT_EQ(-EAGAIN, vfs_write(wr_fd, big_buf, 5000));
  kfree(big_buf);


  KTEST_BEGIN("FIFO: non-block test cleanup");
  vfs_close(rd_fd);
  vfs_close(wr_fd);
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

typedef struct {
  struct apos_pollfd* pfds;
  int nfds;
  int timeout;
  bool finished;
  int result;
} poll_thread_args_t;

static void* do_poll(void* arg) {
  poll_thread_args_t* args = (poll_thread_args_t*)arg;
  args->finished = false;
  args->result = vfs_poll(args->pfds, args->nfds, args->timeout);
  args->finished = true;
  return 0;
}

// Run from fifo_poll_test().
static void fifo_poll_no_writers_test(void) {
  KTEST_BEGIN("FIFO: poll(POLLIN) with no writers (never had writer)");
  struct apos_pollfd pfds[1];
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo2", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  int rd_fd = vfs_open("fifo_test/fifo2", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(rd_fd, 0);
  pfds[0].fd = rd_fd;
  pfds[0].events = POLLIN | POLLRDNORM;
  pfds[0].revents = 123;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(0, pfds[0].revents);

  pfds[0].events = 0;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(0, pfds[0].revents);


  KTEST_BEGIN("FIFO: poll(POLLIN | POLLOUT) with no writers (never had writer)");
  pfds[0].events = POLLIN | POLLOUT;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(0, pfds[0].revents);


  KTEST_BEGIN("FIFO: timing-out poll(POLLIN) with no writers (never had writer)");
  pfds[0].events = POLLIN;
  apos_ms_t start = get_time_ms();
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 50));
  apos_ms_t end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_GE(end - start, 40);
  KEXPECT_LE(end - start, 60);


  KTEST_BEGIN("FIFO: poll(POLLIN) with no writers (writer closed)");
  int wr_fd = vfs_open("fifo_test/fifo2", VFS_O_WRONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(wr_fd, 0);
  KEXPECT_EQ(3, vfs_write(wr_fd, "abc", 3));
  vfs_close(wr_fd);

  pfds[0].events = POLLIN;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, -1));
  KEXPECT_EQ(POLLIN | POLLHUP, pfds[0].revents);

  char buf[10];
  KEXPECT_EQ(3, vfs_read(rd_fd, buf, 10));
  pfds[0].events = POLLIN;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, -1));
  KEXPECT_EQ(POLLHUP, pfds[0].revents);

  pfds[0].events = 0;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(POLLHUP, pfds[0].revents);


  KTEST_BEGIN("FIFO: poll(POLLIN | POLLOUT) with no writers (writer closed)");
  wr_fd = vfs_open("fifo_test/fifo2", VFS_O_WRONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(wr_fd, 0);
  KEXPECT_EQ(3, vfs_write(wr_fd, "abc", 3));
  vfs_close(wr_fd);

  pfds[0].events = POLLIN | POLLOUT;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, -1));
  KEXPECT_EQ(POLLIN | POLLHUP, pfds[0].revents);

  KEXPECT_EQ(3, vfs_read(rd_fd, buf, 10));
  pfds[0].events = POLLIN | POLLOUT;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, -1));
  KEXPECT_EQ(POLLHUP, pfds[0].revents);


  KTEST_BEGIN("FIFO: delayed poll(POLLIN) when last writer goes away");
  wr_fd = vfs_open("fifo_test/fifo2", VFS_O_WRONLY | VFS_O_NONBLOCK);
  pfds[0].events = POLLIN;
  poll_thread_args_t pt_args;
  pt_args.pfds = pfds;
  pt_args.nfds = 1;
  pt_args.timeout = 50;

  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &do_poll, &pt_args));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  vfs_close(wr_fd);
  kthread_join(thread);
  KEXPECT_EQ(1, pt_args.result);
  KEXPECT_EQ(POLLHUP, pfds[0].revents);

  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo2"));
  vfs_close(rd_fd);
}

static void fifo_poll_test(void) {
  KTEST_BEGIN("FIFO: poll on empty FIFO");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  int rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  int wr_fd = vfs_open("fifo_test/fifo", VFS_O_WRONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(rd_fd, 0);
  KEXPECT_GE(wr_fd, 0);

  struct apos_pollfd pfds[2];
  pfds[0].fd = rd_fd;
  pfds[1].fd = wr_fd;
  pfds[0].events = pfds[1].events =
      POLLIN | POLLOUT | POLLPRI | POLLRDNORM | POLLWRNORM;

  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLIN | POLLPRI;
  KEXPECT_EQ(0, vfs_poll(pfds, 2, 0));
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(0, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLOUT | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);


  KTEST_BEGIN("FIFO: poll on FIFO with some data (readable and writable)");
  KEXPECT_EQ(3, vfs_write(wr_fd, "abc", 3));

  pfds[0].events = pfds[1].events = POLLIN | POLLOUT | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN | POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLIN | POLLOUT, pfds[1].revents);

  pfds[0].events = pfds[1].events =
      POLLIN | POLLOUT | POLLPRI | POLLRDNORM | POLLWRNORM;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, pfds[0].revents);
  KEXPECT_EQ(POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLIN | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_EQ(POLLIN, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLOUT | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);


  KTEST_BEGIN("FIFO: poll on almost-full FIFO (readable and writable)");
  int result;
  do {
    result = vfs_write(wr_fd, "x", 1);
  } while (result > 0);
  char* buf = kmalloc(1000);
  KEXPECT_EQ(3, vfs_read(rd_fd, buf, 3));

  pfds[0].events = pfds[1].events = POLLIN | POLLOUT | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN | POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLIN | POLLOUT, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLIN | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_EQ(POLLIN, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLOUT | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);


  KTEST_BEGIN("FIFO: poll on full FIFO (readable, not writable)");
  do {
    result = vfs_write(wr_fd, "abc", 3);
  } while (result > 0);

  pfds[0].events = pfds[1].events = POLLIN | POLLOUT | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_EQ(POLLIN, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLIN | POLLPRI;
  KEXPECT_EQ(2, vfs_poll(pfds, 2, -1));
  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_EQ(POLLIN, pfds[1].revents);

  pfds[0].events = pfds[1].events = POLLOUT | POLLPRI;
  KEXPECT_EQ(0, vfs_poll(pfds, 2, 0));
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(0, pfds[1].revents);
  do {
    result = vfs_read(rd_fd, buf, 1000);
  } while (result > 0);


  KTEST_BEGIN("FIFO: delayed poll (becomes readable)");
  pfds[0].events = pfds[1].events = POLLIN;
  poll_thread_args_t pt_args;
  pt_args.pfds = pfds;
  pt_args.nfds = 2;
  pt_args.timeout = -1;

  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &do_poll, &pt_args));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  KEXPECT_EQ(3, vfs_write(wr_fd, "abc", 3));
  kthread_join(thread);
  KEXPECT_EQ(2, pt_args.result);
  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_EQ(POLLIN, pfds[1].revents);
  KEXPECT_EQ(3, vfs_read(rd_fd, buf, 10));


  KTEST_BEGIN("FIFO: delayed poll (becomes writable)");
  do {
    result = vfs_write(wr_fd, buf, 1000);
  } while (result > 0);
  pfds[0].events = pfds[1].events = POLLOUT;
  pt_args.pfds = pfds;
  pt_args.nfds = 2;
  pt_args.timeout = -1;

  KEXPECT_EQ(0, kthread_create(&thread, &do_poll, &pt_args));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  KEXPECT_EQ(3, vfs_read(rd_fd, buf, 3));
  kthread_join(thread);
  KEXPECT_EQ(2, pt_args.result);
  KEXPECT_EQ(POLLOUT, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  do { result = vfs_read(rd_fd, buf, 1000); } while (result > 0);


  KTEST_BEGIN("FIFO: poll(POLLOUT) with no readers");
  pfds[0].events = pfds[1].events = POLLOUT;
  vfs_close(rd_fd);
  KEXPECT_EQ(1, vfs_poll(pfds + 1, 1, -1));
  KEXPECT_EQ(POLLOUT | POLLERR, pfds[1].revents);

  rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  do { result = vfs_write(wr_fd, buf, 1000); } while (result > 0);
  vfs_close(rd_fd);
  KEXPECT_EQ(1, vfs_poll(pfds + 1, 1, -1));
  KEXPECT_EQ(POLLERR, pfds[1].revents);
  rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  do { result = vfs_read(rd_fd, buf, 1000); } while (result > 0);


  KTEST_BEGIN("FIFO: poll(POLLIN | POLLOUT) with no readers");
  pfds[0].events = pfds[1].events = POLLIN | POLLOUT;
  vfs_close(rd_fd);
  KEXPECT_EQ(1, vfs_poll(pfds + 1, 1, -1));
  KEXPECT_EQ(POLLOUT | POLLERR, pfds[1].revents);

  rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  do { result = vfs_write(wr_fd, buf, 1000); } while (result > 0);
  vfs_close(rd_fd);
  KEXPECT_EQ(1, vfs_poll(pfds + 1, 1, -1));
  KEXPECT_EQ(POLLERR, pfds[1].revents);
  rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  do { result = vfs_read(rd_fd, buf, 1000); } while (result > 0);


  KTEST_BEGIN("FIFO: delayed poll(POLLOUT) when last reader goes away");
  pfds[0].events = pfds[1].events = POLLOUT;
  pt_args.pfds = pfds + 1;
  pt_args.nfds = 1;
  pt_args.timeout = -1;

  do { result = vfs_write(wr_fd, buf, 1000); } while (result > 0);

  KEXPECT_EQ(0, kthread_create(&thread, &do_poll, &pt_args));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  vfs_close(rd_fd);
  kthread_join(thread);
  KEXPECT_EQ(1, pt_args.result);
  KEXPECT_EQ(POLLERR, pfds[1].revents);

  rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  do { result = vfs_read(rd_fd, buf, 1000); } while (result > 0);

  fifo_poll_no_writers_test();

  KTEST_BEGIN("FIFO: poll test cleanup");
  vfs_close(rd_fd);
  vfs_close(wr_fd);
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
  kfree(buf);
}

static void concurrent_close_poll_test(void) {
  KTEST_BEGIN("FIFO: close FIFO fd during poll()");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  int rd_fd = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_GE(rd_fd, 0);

  struct apos_pollfd pfd;
  pfd.fd = rd_fd;
  pfd.events = POLLIN | POLLOUT | POLLPRI | POLLRDNORM | POLLWRNORM;

  poll_thread_args_t pt_args;
  pt_args.pfds = &pfd;
  pt_args.nfds = 1;
  pt_args.timeout = -1;

  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, &do_poll, &pt_args));
  scheduler_make_runnable(thread);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  vfs_close(rd_fd);
  kthread_join(thread);
  KEXPECT_EQ(1, pt_args.result);
  KEXPECT_EQ(POLLNVAL, pfd.revents);
  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

static void out_of_resources_test(void) {
  KTEST_BEGIN("FIFO: out of files in open()");
  KEXPECT_EQ(0, vfs_mkdir("fifo_test", VFS_S_IRWXU));
  KEXPECT_EQ(0, vfs_mknod("fifo_test/fifo", VFS_S_IFIFO | VFS_S_IRWXU, 0));

  vfs_set_force_no_files(true);
  int result = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_EQ(-ENFILE, result);
  vfs_set_force_no_files(false);

  KTEST_BEGIN("FIFO: out of FDs in open()");
  struct rlimit lim;
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_NOFILE, &lim));
  const struct rlimit orig_lim = lim;
  lim.rlim_cur = 0;
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_NOFILE, &lim));
  result = vfs_open("fifo_test/fifo", VFS_O_RDONLY | VFS_O_NONBLOCK);
  KEXPECT_EQ(-EMFILE, result);
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_NOFILE, &orig_lim));

  KEXPECT_EQ(0, vfs_unlink("fifo_test/fifo"));
  KEXPECT_EQ(0, vfs_rmdir("fifo_test"));
}

void vfs_fifo_test(void) {
  KTEST_SUITE_BEGIN("VFS FIFO test");
  const int initial_cache_size = vfs_cache_size();
  ksigset_t old_mask, new_mask;
  ksigemptyset(&new_mask);
  ksigaddset(&new_mask, SIGCHLD);
  proc_sigprocmask(SIG_BLOCK, &new_mask, &old_mask);

  mknod_test();
  stat_test();
  open_test();
  read_write_test();
  interrupt_test();
  nonblock_test();
  fifo_poll_test();
  concurrent_close_poll_test();
  out_of_resources_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());

  proc_sigprocmask(SIG_SETMASK, &old_mask, 0x0);
}
