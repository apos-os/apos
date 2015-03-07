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
#include "proc/sleep.h"
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

#define CHARDEV_NUM_DEVS 3

typedef struct {
  poll_event_t event;
  short events;
  short future_events;
  int poll_sleep_ms;
} fake_dev_t;

typedef struct {
  fake_dev_t fake_devs[CHARDEV_NUM_DEVS];
  char_dev_t dev[CHARDEV_NUM_DEVS];
  apos_dev_t dev_id[CHARDEV_NUM_DEVS];
  int fd[CHARDEV_NUM_DEVS];
} chardev_args_t;

static void set_cd_events(chardev_args_t* args, int idx, short events) {
  poll_init_event(&args->fake_devs[idx].event);
  args->fake_devs[idx].events = events;
  args->fake_devs[idx].poll_sleep_ms = 0;
  args->dev[idx].dev_data = &args->fake_devs[idx];
}

static int cd_fake_dev_poll(char_dev_t* dev, short event_mask,
                            poll_state_t* poll) {
  fake_dev_t* fdev = (fake_dev_t*)dev->dev_data;
  if (fdev->poll_sleep_ms > 0)
    ksleep(fdev->poll_sleep_ms);

  if ((fdev->events & event_mask) || !poll)
    return fdev->events & event_mask;
  else
    return poll_add_event(poll, &fdev->event, event_mask);
}

static void do_trigger_fake_dev(void* arg) {
  fake_dev_t* fdev = (fake_dev_t*)arg;
  fdev->events = fdev->future_events;
  poll_trigger_event(&fdev->event, fdev->events);
}

static void do_non_trigger_fake_dev(void* arg) {
  fake_dev_t* fdev = (fake_dev_t*)arg;
  fdev->events = fdev->future_events;
}

// Trigger a fake_dev's event, either synchronously or in the future.
static void trigger_fake_dev(fake_dev_t* fdev, short events, int delay_ms) {
  fdev->future_events = events;
  if (delay_ms <= 0)
    do_trigger_fake_dev(fdev);
  else
    register_event_timer(get_time_ms() + delay_ms, &do_trigger_fake_dev, fdev,
                         NULL);
}

// Schedule an event to happen on the device in the future that won't trigger
// the poll (this shouldn't happen in practice, but is useful for tests).
static void fake_dev_non_trigger_event(fake_dev_t* fdev, short events,
                                       int delay_ms) {
  fdev->future_events = events;
  register_event_timer(get_time_ms() + delay_ms, &do_non_trigger_fake_dev, fdev,
                       NULL);
}

// As above, but doesn't update the events (to simulate triggering the event,
// but someone else consuming it before the poll() gets around).
static void do_trigger_fake_devB(void* arg) {
  fake_dev_t* fdev = (fake_dev_t*)arg;
  poll_trigger_event(&fdev->event, fdev->future_events);
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

  KTEST_BEGIN("poll(): basic timeout test");
  set_cd_events(args, 0, 0);
  pfds[0].revents = 521;
  uint32_t start = get_time_ms();
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 100));
  KEXPECT_GE(get_time_ms() - start, 100);
  KEXPECT_EQ(0, pfds[0].revents);

  KTEST_BEGIN("poll(): delayed trigger wake up but no event test");
  set_cd_events(args, 0, 0);
  args->fake_devs[0].future_events = POLLIN;
  register_event_timer(get_time_ms() + 50, &do_trigger_fake_devB,
                       &args->fake_devs[0], NULL);

  pfds[0].fd = args->fd[0];
  pfds[0].events = POLLIN | POLLOUT;
  start = get_time_ms();
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 100));
  uint32_t elapsed = get_time_ms() - start;

  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_GE(elapsed, 100);
  KEXPECT_LE(elapsed, 120);


  KTEST_BEGIN("poll(): basic delayed trigger");
  set_cd_events(args, 0, 0);
  trigger_fake_dev(&args->fake_devs[0], POLLIN, 50);

  pfds[0].fd = args->fd[0];
  pfds[0].events = POLLIN | POLLOUT;
  start = get_time_ms();
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 100));
  elapsed = get_time_ms() - start;
  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_GE(elapsed, 40);
  KEXPECT_LE(elapsed, 70);


  KTEST_BEGIN("poll(): basic delayed trigger (masked event)");
  set_cd_events(args, 0, 0);
  trigger_fake_dev(&args->fake_devs[0], POLLIN, 50);

  pfds[0].fd = args->fd[0];
  pfds[0].events = POLLOUT;
  start = get_time_ms();
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 100));
  elapsed = get_time_ms() - start;
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_GE(elapsed, 100);
  KEXPECT_LE(elapsed, 120);
}

static void multi_fd_test(chardev_args_t* args) {
  struct pollfd pfds[5];
  KTEST_BEGIN("poll(): basic multi-fd test");
  set_cd_events(args, 0, POLLIN);
  set_cd_events(args, 1, POLLOUT);
  set_cd_events(args, 2, POLLOUT);

  for (int i= 0; i < 3; ++i) {
    pfds[i].fd = args->fd[i];
    pfds[i].revents = 123;
  }
  pfds[0].events = POLLIN | POLLOUT;
  pfds[1].events = POLLIN;
  pfds[2].events = POLLOUT;
  KEXPECT_EQ(2, vfs_poll(pfds, 3, 0));
  KEXPECT_EQ(2, vfs_poll(pfds, 3, -1));

  KEXPECT_EQ(POLLIN, pfds[0].revents);
  KEXPECT_EQ(0, pfds[1].revents);
  KEXPECT_EQ(POLLOUT, pfds[2].revents);


  KTEST_BEGIN("poll(): delayed multi-fd");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].fd = args->fd[i];
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 30);
  uint32_t start = get_time_ms();
  KEXPECT_EQ(1, vfs_poll(pfds, 3, -1));
  uint32_t end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);
  KEXPECT_GE(end - start, 20);
  KEXPECT_LE(end - start, 40);


  KTEST_BEGIN("poll(): delayed multi-fd (positive timeout)");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 30);
  start = get_time_ms();
  KEXPECT_EQ(1, vfs_poll(pfds, 3, 60));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);
  KEXPECT_GE(end - start, 20);
  KEXPECT_LE(end - start, 40);


  KTEST_BEGIN("poll(): delayed multi-fd (multiple fds ready)");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 40);
  fake_dev_non_trigger_event(&args->fake_devs[2], POLLIN, 20);
  start = get_time_ms();
  KEXPECT_EQ(2, vfs_poll(pfds, 3, -1));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(POLLIN, pfds[2].revents);
  KEXPECT_GE(end - start, 30);
  KEXPECT_LE(end - start, 50);


  KTEST_BEGIN("poll(): delayed multi-fd (another fd w/ masked event)");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 40);
  fake_dev_non_trigger_event(&args->fake_devs[2], POLLIN, 20);
  pfds[2].events = POLLOUT;

  start = get_time_ms();
  KEXPECT_EQ(1, vfs_poll(pfds, 3, -1));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);
  KEXPECT_GE(end - start, 30);
  KEXPECT_LE(end - start, 50);


  KTEST_BEGIN("poll(): delayed multi-fd (fd w/ masked then unmasked event)");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLOUT;
    pfds[i].revents = 123;
  }

  set_cd_events(args, 1, POLLIN);
  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 40);

  start = get_time_ms();
  KEXPECT_EQ(1, vfs_poll(pfds, 3, -1));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);
  KEXPECT_GE(end - start, 30);
  KEXPECT_LE(end - start, 50);


  KTEST_BEGIN("poll(): delayed multi-fd B");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLOUT;
    pfds[i].revents = 123;
  }

  set_cd_events(args, 1, POLLIN);
  set_cd_events(args, 2, POLLIN);
  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 40);
  fake_dev_non_trigger_event(&args->fake_devs[2], POLLOUT, 20);

  start = get_time_ms();
  KEXPECT_EQ(2, vfs_poll(pfds, 3, -1));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(POLLOUT, pfds[2].revents);
  KEXPECT_GE(end - start, 30);
  KEXPECT_LE(end - start, 50);


  KTEST_BEGIN("poll(): non-blocking multi-fd (no events)");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  KEXPECT_EQ(0, vfs_poll(pfds, 3, 0));
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(0, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);


  KTEST_BEGIN("poll(): timeout multi-fd");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  start = get_time_ms();
  KEXPECT_EQ(0, vfs_poll(pfds, 3, 30));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(0, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);
  KEXPECT_GE(end - start, 20);
  KEXPECT_LE(end - start, 40);


  // Test if an event isn't pending, but triggers before the poll finishes going
  // through all the fds and enters its sleep.
  KTEST_BEGIN("poll(): delayed multi-fd, triggers before sleep");
  for (int i = 0; i < CHARDEV_NUM_DEVS; ++i) {
    set_cd_events(args, i, 0);
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 123;
  }

  trigger_fake_dev(&args->fake_devs[1], POLLOUT, 20);
  args->fake_devs[2].poll_sleep_ms = 40;
  start = get_time_ms();
  KEXPECT_EQ(1, vfs_poll(pfds, 3, -1));
  end = get_time_ms();
  KEXPECT_EQ(0, pfds[0].revents);
  KEXPECT_EQ(POLLOUT, pfds[1].revents);
  KEXPECT_EQ(0, pfds[2].revents);
  KEXPECT_GE(end - start, 70);
  KEXPECT_LE(end - start, 90);
}

static void make_staticval_dev(char_dev_t* dev, apos_dev_t* id, int* fd) {
  dev->read = NULL;
  dev->write = NULL;
  dev->poll = &cd_fake_dev_poll;
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
  multi_fd_test(&args);

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
