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

void poll_test(void) {
  KTEST_SUITE_BEGIN("poll() tests");
  vfs_mkdir("_poll_test_dir", VFS_S_IRWXU);

  poll_file_test();
  poll_dir_test();

  KEXPECT_EQ(0, vfs_rmdir("_poll_test_dir"));
}
