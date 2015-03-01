// Copyright 2015 Andrew Oates.  All Rights Reserved.
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
#include "vfs/poll.h"

#include "common/kprintf.h"
#include "dev/dev.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "vfs/vfs.h"

// Tests
//  - always events
//  - out-of-memory
//  - already triggered
//  - delayed trigger
//  - mixed delayed and normal trigger
//  - negative fd
//  - masked (already triggered)
//  - masked (delayed triggered)
//  - mixed mask (already and delayed)
//  - interrupted by signal
//  - too-high fd (ignored)
//  - too-low fd (ignored)
//  - much too-high fd (EINVAL)
//  - fd changes underneath the call
//  - read-only, write-only, etc (looks like it should succeed? at least on
//  normal files)
//  - all file types: directory, etc
//  - timeout
//  - pipes
//  - bad device

static void poll_file_test(void) {
  KTEST_BEGIN("poll(): regular file test");
  int fd =
      vfs_open("_poll_test_dir/file", VFS_O_CREAT | VFS_O_RDONLY, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLOUT | POLLERR | POLLNVAL | POLLPRI;
  pfd.revents = 123;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 1000));
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, -1));

  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(POLLIN | POLLOUT | POLLERR | POLLNVAL | POLLPRI, pfd.events);
  KEXPECT_EQ(POLLIN | POLLOUT, pfd.revents);

  KTEST_BEGIN("poll(): regular file test (POLLIN and POLLPRI)");
  pfd.events = POLLIN | POLLPRI;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(POLLIN | POLLPRI, pfd.events);
  KEXPECT_EQ(POLLIN, pfd.revents);

  KTEST_BEGIN("poll(): regular file test (invalid event)");
  pfd.events = 5000;
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(5000, pfd.events);
  KEXPECT_EQ(0, pfd.revents);

  KEXPECT_EQ(0, vfs_unlink("_poll_test_dir/file"));
}

static void poll_dir_test(void) {
  KTEST_BEGIN("poll(): directory test (no events)");
  int fd = vfs_open("_poll_test_dir", VFS_O_RDONLY);
  KEXPECT_GE(fd, 0);

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = 0;
  pfd.revents = 123;
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(0, pfd.events);
  KEXPECT_EQ(0, pfd.revents);


  KTEST_BEGIN("poll(): directory test (POLLIN)");
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 123;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(POLLIN, pfd.events);
  KEXPECT_EQ(POLLNVAL, pfd.revents);


  KTEST_BEGIN("poll(): directory test (POLLOUT)");
  pfd.fd = fd;
  pfd.events = POLLOUT;
  pfd.revents = 123;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(POLLOUT, pfd.events);
  KEXPECT_EQ(POLLNVAL, pfd.revents);


  KTEST_BEGIN("poll(): directory test (POLLOUT | POLLNVAL)");
  pfd.fd = fd;
  pfd.events = POLLOUT | POLLNVAL;
  pfd.revents = 123;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(POLLOUT | POLLNVAL, pfd.events);
  KEXPECT_EQ(POLLNVAL, pfd.revents);


  KTEST_BEGIN("poll(): directory test (invalid event)");
  pfd.fd = fd;
  pfd.events = 532;
  pfd.revents = 123;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(fd, pfd.fd);
  KEXPECT_EQ(532, pfd.events);
  KEXPECT_EQ(POLLNVAL, pfd.revents);
}

#define CHARDEV_NUM_DEVS 1

typedef struct {
  char_dev_t dev[CHARDEV_NUM_DEVS];
  apos_dev_t dev_id[CHARDEV_NUM_DEVS];
  int fd[CHARDEV_NUM_DEVS];
} chardev_args_t;

static void set_cd_events(chardev_args_t* args, int idx, short events) {
  args->dev[idx].dev_data = (void*)((intptr_t)events);
}

static void basic_cd_test(chardev_args_t* args) {
  struct pollfd pfds[5];

  KTEST_BEGIN("poll(): basic POLLIN chardev test");
  set_cd_events(args, 0, POLLIN);

  pfds[0].fd = args->fd[0];
  pfds[0].events = POLLIN | POLLOUT;
  pfds[0].revents = 521;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(args->fd[0], pfds[0].fd);
  KEXPECT_EQ(POLLIN | POLLOUT, pfds[0].events);
  KEXPECT_EQ(POLLIN, pfds[0].revents);

  KTEST_BEGIN("poll(): basic POLLOUT chardev test");
  set_cd_events(args, 0, POLLOUT);
  pfds[0].revents = 521;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(POLLOUT, pfds[0].revents);

  KTEST_BEGIN("poll(): basic POLLIN/POLLOUT chardev test");
  set_cd_events(args, 0, POLLIN | POLLOUT);
  pfds[0].revents = 521;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(POLLIN | POLLOUT, pfds[0].revents);
}

static int cd_staticval_poll(char_dev_t* dev, short event_mask,
                             poll_state_t* poll) {
  return ((short)dev->dev_data) & event_mask;
}

static void make_staticval_dev(char_dev_t* dev, apos_dev_t* id, int* fd) {
  dev->read = NULL;
  dev->write = NULL;
  dev->poll = &cd_staticval_poll;
  dev->dev_data = 0;

  *id = makedev(DEVICE_MAJOR_TTY, DEVICE_ID_UNKNOWN);
  KEXPECT_EQ(0, dev_register_char(dev, id));

  char dev_name[20];
  ksprintf(dev_name, "/dev/tty%d", minor(*id));
  *fd = vfs_open(dev_name, VFS_O_RDONLY);
  KEXPECT_GE(*fd, 0);
}

static void destroy_staticval_dev(const apos_dev_t id, const int fd) {
  KEXPECT_EQ(0, dev_unregister_char(id));
  KEXPECT_EQ(0, vfs_close(fd));
}

static void char_dev_tests(void) {
  chardev_args_t args;

  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i)
    make_staticval_dev(&args.dev[i], &args.dev_id[i], &args.fd[i]);

  basic_cd_test(&args);

  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i)
    destroy_staticval_dev(args.dev_id[i], args.fd[i]);
}

void poll_test(void) {
  KTEST_SUITE_BEGIN("poll() tests");
  vfs_mkdir("_poll_test_dir", VFS_S_IRWXU);

  poll_file_test();
  poll_dir_test();
  char_dev_tests();

  KEXPECT_EQ(0, vfs_rmdir("_poll_test_dir"));
}
