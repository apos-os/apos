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

#include "common/ascii.h"
#include "common/kprintf.h"
#include "dev/ld.h"
#include "dev/tty.h"
#include "dev/termios.h"
#include "dev/timer.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "proc/tcgroup.h"
#include "proc/wait.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "user/include/apos/termios.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"

static void do_nothing(void* arg) {}

static int sig_is_pending(process_t* proc, int sig) {
  ksigset_t pending = proc_pending_signals(proc);
  return ksigismember(&pending, sig);
}

static void sink(void* arg, char c) {
  (*(int*)arg)++;
}

typedef struct {
  ld_t* ld;
  apos_dev_t tty;
} args_t;

static void ld_signals_test(void* arg) {
  ld_t* const test_ld = ((args_t*)arg)->ld;
  const apos_dev_t test_tty = ((args_t*)arg)->tty;

  KTEST_BEGIN("TTY: ctrl-C ignored by ld not attached to a TTY");
  KEXPECT_EQ(proc_current()->id, proc_setsid());
  int sink_counter = 0;
  ld_set_sink(test_ld, &sink, &sink_counter);

  ld_provide(test_ld, ASCII_ETX);
  KEXPECT_EQ(2, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGINT));


  KTEST_BEGIN("TTY: ctrl-C ignored if TTY isn't a CTTY");
  const kpid_t childA = proc_fork(&do_nothing, NULL);
  const kpid_t childB = proc_fork(&do_nothing, NULL);
  const kpid_t childC = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(childB, 0));
  KEXPECT_EQ(0, setpgid(childC, childB));

  sink_counter = 0;
  ld_provide(test_ld, 0x03);
  KEXPECT_EQ(2, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGINT));


  KTEST_BEGIN("TTY: ctrl-C ignored if no fg process group");
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(test_tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  sink_counter = 0;
  ld_provide(test_ld, 0x03);
  KEXPECT_EQ(2, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGINT));


  KTEST_BEGIN("TTY: ctrl-C sends SIGINT to fg process group");
  ksigset_t sigset, old_sigmask;
  ksigemptyset(&sigset);
  ksigaddset(&sigset, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &sigset, &old_sigmask));

  KEXPECT_EQ(0, proc_tcsetpgrp(fd, childB));

  sink_counter = 0;
  ld_provide(test_ld, 0x03);
  KEXPECT_EQ(2, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGINT));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childB), SIGINT));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childC), SIGINT));

  KTEST_BEGIN("TTY: ctrl-Z sends SIGTSTP to fg process group");
  sink_counter = 0;
  ld_provide(test_ld, ASCII_SUB);
  KEXPECT_EQ(2, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTSTP));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTSTP));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childB), SIGTSTP));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childC), SIGTSTP));

  KTEST_BEGIN("TTY: ctrl-\\ sends SIGQUIT to fg process group");
  sink_counter = 0;
  ld_provide(test_ld, ASCII_FS);
  KEXPECT_EQ(2, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGQUIT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGQUIT));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childB), SIGQUIT));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childC), SIGQUIT));

  proc_wait(NULL);
  proc_wait(NULL);
  proc_wait(NULL);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_sigmask, NULL));
}

static void ld_signals_isig_flag_test(void* arg) {
  ld_t* const test_ld = ((args_t*)arg)->ld;
  const apos_dev_t test_tty = ((args_t*)arg)->tty;

  struct ktermios term;
  ld_get_termios(test_ld, &term);
  const struct ktermios orig_term = term;

  KTEST_BEGIN("TTY: ctrl-C/SIGINT disabled if ISIG isn't set");
  term.c_lflag &= ~ISIG;
  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &term));

  KEXPECT_EQ(proc_current()->id, proc_setsid());
  int sink_counter = 0;
  ld_set_sink(test_ld, &sink, &sink_counter);

  const kpid_t childA = proc_fork(&do_nothing, NULL);
  const kpid_t childB = proc_fork(&do_nothing, NULL);
  const kpid_t childC = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(childB, 0));
  KEXPECT_EQ(0, setpgid(childC, childB));

  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(test_tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  ksigset_t sigset, old_sigmask;
  ksigemptyset(&sigset);
  ksigaddset(&sigset, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &sigset, &old_sigmask));

  KEXPECT_EQ(0, proc_tcsetpgrp(fd, proc_current()->id));

  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, 0x03);
  ld_provide(test_ld, 'b');
  ld_provide(test_ld, '\x04');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGINT));

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x03" "b", buf);


  KTEST_BEGIN("TTY: ctrl-Z/SIGTSTP disabled if ISIG isn't set");
  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, ASCII_SUB);
  ld_provide(test_ld, 'b');
  ld_provide(test_ld, '\x04');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTSTP));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTSTP));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGTSTP));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGTSTP));

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x1a" "b", buf);

  KTEST_BEGIN("TTY: ctrl-\\/SIGQUIT disabled if ISIG isn't set");
  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, ASCII_FS);
  ld_provide(test_ld, 'b');
  ld_provide(test_ld, '\x04');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGQUIT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGQUIT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGQUIT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGQUIT));

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x1c" "b", buf);

  KTEST_BEGIN("TTY: ctrl-C/SIGINT sent in non-canon mode if ISIG isn't set");
  term.c_lflag &= ~ICANON;
  term.c_lflag |= ISIG;
  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &term));
  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, ASCII_ETX);
  ld_provide(test_ld, 'b');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGINT));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childA), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGINT));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGINT));

  kmemset(buf, 0, 10);
  KEXPECT_EQ(1, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("b", buf);

  proc_wait(NULL);
  proc_wait(NULL);
  proc_wait(NULL);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_sigmask, NULL));

  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &orig_term));
}

// This is really an ld test, but it's easier to write here (to test the signal
// generation).
static void ld_signals_cc_c_test(void* arg) {
  ld_t* const test_ld = ((args_t*)arg)->ld;
  const apos_dev_t test_tty = ((args_t*)arg)->tty;

  struct ktermios term;
  ld_get_termios(test_ld, &term);
  const struct ktermios orig_term = term;

  KTEST_BEGIN("ld: change INTR character");
  KEXPECT_EQ(proc_current()->id, proc_setsid());
  int sink_counter = 0;
  ld_set_sink(test_ld, &sink, &sink_counter);

  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(test_tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  ksigset_t sigset, old_sigmask;
  ksigemptyset(&sigset);
  ksigaddset(&sigset, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &sigset, &old_sigmask));
  KEXPECT_EQ(0, proc_tcsetpgrp(fd, proc_current()->id));

  term.c_cc[VINTR] = 'p';
  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &term));

  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, 0x03);
  ld_provide(test_ld, 'b');
  ld_provide(test_ld, '\x04');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGINT));

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x03" "b", buf);

  ld_provide(test_ld, 'x');
  ld_provide(test_ld, 'p');
  KEXPECT_EQ(-EAGAIN, ld_read(test_ld, buf, 10, VFS_O_NONBLOCK));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGINT));


  KTEST_BEGIN("ld: change QUIT character");
  term = orig_term;
  term.c_cc[VQUIT] = 'q';
  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &term));

  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, 0x1c);
  ld_provide(test_ld, 'b');
  ld_provide(test_ld, '\x04');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGQUIT));

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x1c" "b", buf);

  ld_provide(test_ld, 'x');
  ld_provide(test_ld, 'q');
  KEXPECT_EQ(-EAGAIN, ld_read(test_ld, buf, 10, VFS_O_NONBLOCK));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGQUIT));


  KTEST_BEGIN("ld: change SUSP character");
  term = orig_term;
  term.c_cc[VSUSP] = 'q';
  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &term));

  sink_counter = 0;
  ld_provide(test_ld, 'a');
  ld_provide(test_ld, 0x1a);
  ld_provide(test_ld, 'b');
  ld_provide(test_ld, '\x04');
  KEXPECT_EQ(4, sink_counter);
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTSTP));

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10, 0));
  KEXPECT_STREQ("a\x1a" "b", buf);

  ld_provide(test_ld, 'x');
  ld_provide(test_ld, 'q');
  KEXPECT_EQ(-EAGAIN, ld_read(test_ld, buf, 10, VFS_O_NONBLOCK));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTSTP));


  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_sigmask, NULL));

  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &orig_term));
}

static void ld_signals_test_runner(void* arg) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  kpid_t child = proc_fork(&ld_signals_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&ld_signals_isig_flag_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&ld_signals_cc_c_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(args.tty);
  ld_destroy(args.ld);
}

// Tests for the terminal control functions.  These don't test much of the
// functionality itself, since that's covered by the underlying ld tests.
static void termios_test(void* arg) {
  args_t* args = (args_t*)arg;
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(args->tty));

  KTEST_BEGIN("tty: tcgetattr() defaults");
  const int tty_fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_NOCTTY);
  KEXPECT_GE(tty_fd, 0);
  const int other_fd =
      vfs_open("_tty_test_file", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(other_fd, 0);

  struct ktermios t;
  kmemset(&t, 0xFF, sizeof(struct ktermios));
  KEXPECT_EQ(0, tty_tcgetattr(tty_fd, &t));
  KEXPECT_EQ(0x04, t.c_cc[VEOF]);
  KEXPECT_NE(0, t.c_lflag & ICANON);


  KTEST_BEGIN("tty: tcgetattr() invalid or non-TTY fd");
  KEXPECT_EQ(-EBADF, tty_tcgetattr(-1, &t));
  KEXPECT_EQ(-EBADF, tty_tcgetattr(other_fd + 1, &t));
  KEXPECT_EQ(-EBADF, tty_tcgetattr(1000000, &t));
  KEXPECT_EQ(-ENOTTY, tty_tcgetattr(other_fd, &t));


  KTEST_BEGIN("tty: tcsetattr(TCSANOW)");
  t.c_cc[VINTR] = 'p';
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(0, tty_tcsetattr(tty_fd, TCSANOW, &t));
  kmemset(&t, 0, sizeof(t));
  KEXPECT_EQ(0, tty_tcgetattr(tty_fd, &t));
  KEXPECT_EQ('p', t.c_cc[VINTR]);
  char buf[10];
  KEXPECT_EQ(1, vfs_read(tty_fd, &buf, 10));


  KTEST_BEGIN("tty: tcsetattr(TCSAFLUSH)");
  t.c_cc[VINTR] = 'q';
  ld_provide(args->ld, 'b');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(0, tty_tcsetattr(tty_fd, TCSAFLUSH, &t));
  kmemset(&t, 0, sizeof(t));
  KEXPECT_EQ(0, tty_tcgetattr(tty_fd, &t));
  KEXPECT_EQ('q', t.c_cc[VINTR]);
  // Ideally we'd read from the tty_fd, but that would block.
  KEXPECT_EQ(-EAGAIN, ld_read(args->ld, buf, 10, VFS_O_NONBLOCK));


  KTEST_BEGIN("tty: tcsetattr() invalid or non-TTY fd");
  KEXPECT_EQ(-EBADF, tty_tcsetattr(-1, TCSANOW, &t));
  KEXPECT_EQ(-EBADF, tty_tcsetattr(other_fd + 1, TCSANOW, &t));
  KEXPECT_EQ(-EBADF, tty_tcsetattr(1000000, TCSANOW, &t));
  KEXPECT_EQ(-ENOTTY, tty_tcsetattr(other_fd, TCSANOW, &t));

  KTEST_BEGIN("tty: tcsetattr() invalid optional_actions");
  KEXPECT_EQ(-EINVAL, tty_tcsetattr(tty_fd, 200, &t));


  KTEST_BEGIN("tty: tcdrain()");
  KEXPECT_EQ(0, tty_tcdrain(tty_fd));

  KTEST_BEGIN("tty: tcdrain() invalid or non-TTY fd");
  KEXPECT_EQ(-EBADF, tty_tcdrain(-1));
  KEXPECT_EQ(-EBADF, tty_tcdrain(other_fd + 1));
  KEXPECT_EQ(-EBADF, tty_tcdrain(1000000));
  KEXPECT_EQ(-ENOTTY, tty_tcdrain(other_fd));


  KTEST_BEGIN("tty: tcflush(TCIFLUSH)");
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(0, tty_tcflush(tty_fd, TCIFLUSH));
  KEXPECT_EQ(-EAGAIN, ld_read(args->ld, buf, 10, VFS_O_NONBLOCK));


  KTEST_BEGIN("tty: tcflush(TCOFLUSH)");
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(0, tty_tcflush(tty_fd, TCOFLUSH));
  KEXPECT_EQ(1, vfs_read(tty_fd, buf, 10));


  KTEST_BEGIN("tty: tcflush() invalid or non-TTY fd");
  KEXPECT_EQ(-EBADF, tty_tcflush(-1, TCIFLUSH));
  KEXPECT_EQ(-EBADF, tty_tcflush(other_fd + 1, TCIFLUSH));
  KEXPECT_EQ(-EBADF, tty_tcflush(1000000, TCIFLUSH));
  KEXPECT_EQ(-ENOTTY, tty_tcflush(other_fd, TCIFLUSH));

  KTEST_BEGIN("tty: tcflush() invalid action");
  KEXPECT_EQ(-EINVAL, tty_tcflush(tty_fd, 200));


  vfs_close(tty_fd);
  vfs_close(other_fd);
  KEXPECT_EQ(0, vfs_unlink("_tty_test_file"));
}

// TODO(aoates): move the read/write from bg tests here as well.
static void termios_bg_pgrp_test(void* arg) {
  args_t* args = (args_t*)arg;
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(args->tty));

  KTEST_BEGIN("tty: setup for background pgroup tests");
  ksigset_t kSigTtouSet;
  ksigemptyset(&kSigTtouSet);
  ksigaddset(&kSigTtouSet, SIGTTOU);

  KEXPECT_EQ(proc_current()->id, proc_setsid());

  ksigset_t ttou_mask;
  ksigemptyset(&ttou_mask);
  ksigaddset(&ttou_mask, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &ttou_mask, NULL));

  const int tty_fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(tty_fd, 0);

  kpid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(child, child));
  KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, child));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &ttou_mask, NULL));

  kpid_t child_in_grp = proc_fork(&do_nothing, NULL);


  KTEST_BEGIN("tty: tcgetattr() from background pgroup");
  struct ktermios t;
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(child_in_grp), SIGTTOU));
  KEXPECT_EQ(0, tty_tcgetattr(tty_fd, &t));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(child_in_grp), SIGTTOU));


  KTEST_BEGIN("tty: tcsetattr() from background pgroup");
  t.c_cc[VINTR] = 'x';
  KEXPECT_EQ(-EINTR, tty_tcsetattr(tty_fd, TCSANOW, &t));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(1, sig_is_pending(proc_get(child_in_grp), SIGTTOU));
  proc_suppress_signal(proc_current(), SIGTTOU);
  proc_suppress_signal(proc_get(child_in_grp), SIGTTOU);

  KEXPECT_EQ(0, tty_tcgetattr(tty_fd, &t));
  KEXPECT_NE('x', t.c_cc[VINTR]);

  // Verify the arg check happens first.
  KEXPECT_EQ(-EINVAL, tty_tcsetattr(tty_fd, 50, &t));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));


  KTEST_BEGIN("tty: tcdrain() from background pgroup");
  KEXPECT_EQ(-EINTR, tty_tcdrain(tty_fd));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(1, sig_is_pending(proc_get(child_in_grp), SIGTTOU));
  proc_suppress_signal(proc_current(), SIGTTOU);
  proc_suppress_signal(proc_get(child_in_grp), SIGTTOU);


  KTEST_BEGIN("tty: tcflush() from background pgroup");
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(-EINTR, tty_tcflush(tty_fd, TCIOFLUSH));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(1, sig_is_pending(proc_get(child_in_grp), SIGTTOU));
  proc_suppress_signal(proc_current(), SIGTTOU);
  proc_suppress_signal(proc_get(child_in_grp), SIGTTOU);

  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &ttou_mask, NULL));
  KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, proc_current()->id));

  char buf[10];
  KEXPECT_EQ(1, ld_read(args->ld, buf, 10, VFS_O_NONBLOCK));
  KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, child));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &ttou_mask, NULL));

  // Verify the arg check happens first.
  KEXPECT_EQ(-EINVAL, tty_tcflush(tty_fd, 50));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));

  KEXPECT_EQ(child_in_grp, proc_waitpid(child_in_grp, NULL, 0));
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));

  vfs_close(tty_fd);
}

static void tty_truncate_test(void* arg) {
  args_t* args = (args_t*)arg;
  char tty_name[20];
  char buf[10];
  ksprintf(tty_name, "/dev/tty%d", kminor(args->tty));

  KTEST_BEGIN("vfs_truncate(): on TTY test");
  int tty_fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(tty_fd, 0);
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, 'b');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(0, vfs_truncate(tty_name, 1));
  KEXPECT_EQ(2, vfs_read(tty_fd, buf, 10));

  KTEST_BEGIN("vfs_ftruncate(): on TTY test");
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, 'b');
  ld_provide(args->ld, '\x04');
  KEXPECT_EQ(0, vfs_ftruncate(tty_fd, 1));
  KEXPECT_EQ(2, vfs_read(tty_fd, buf, 10));

  KTEST_BEGIN("vfs_open(): O_TRUNC on TTY test");
  ld_provide(args->ld, 'a');
  ld_provide(args->ld, 'b');
  ld_provide(args->ld, '\x04');
  int trunc_fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_TRUNC);
  KEXPECT_GE(trunc_fd, 0);
  KEXPECT_EQ(0, vfs_close(trunc_fd));
  KEXPECT_EQ(2, vfs_read(tty_fd, buf, 10));

  vfs_close(tty_fd);
}

static void termios_test_runner(void* arg) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  int sink_counter = 0;
  ld_set_sink(args.ld, &sink, &sink_counter);

  kpid_t child = proc_fork(&termios_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&termios_bg_pgrp_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&tty_truncate_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(args.tty);
  ld_destroy(args.ld);
}

static void tty_nonblock_test(void) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  int sink_counter = 0;
  ld_set_sink(args.ld, &sink, &sink_counter);

  KTEST_BEGIN("TTY: O_NONBLOCK (reading)");
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(args.tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_NONBLOCK | VFS_O_NOCTTY);
  KEXPECT_GE(fd, 0);
  char buf[10];
  KEXPECT_EQ(-EAGAIN, vfs_read(fd, buf, 10));
  ld_provide(args.ld, 'x');
  ld_provide(args.ld, '\n');
  KEXPECT_EQ(2, vfs_read(fd, buf, 10));
  KEXPECT_EQ(-EAGAIN, vfs_read(fd, buf, 10));

  KTEST_BEGIN("TTY: O_NONBLOCK (writing)");
  KEXPECT_EQ(5, vfs_write(fd, "abcde", 5));

  vfs_close(fd);

  tty_destroy(args.tty);
  ld_destroy(args.ld);
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

static void tty_poll_test(void) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  int sink_counter = 0;
  ld_set_sink(args.ld, &sink, &sink_counter);

  KTEST_BEGIN("TTY: basic poll (writable but not readable)");
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(args.tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_NOCTTY);
  KEXPECT_GE(fd, 0);

  struct apos_pollfd pfds[2];
  pfds[0].fd = fd;
  pfds[0].events = KPOLLIN | KPOLLOUT;

  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(KPOLLOUT, pfds[0].revents);

  pfds[0].events = KPOLLIN | KPOLLRDNORM;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(0, pfds[0].revents);


  KTEST_BEGIN("TTY: basic poll (readable and writable)");
  ld_provide(args.ld, 'x');

  pfds[0].events = KPOLLIN;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(0, pfds[0].revents);

  ld_provide(args.ld, '\n');
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(KPOLLIN, pfds[0].revents);

  pfds[0].events = KPOLLIN | KPOLLRDNORM;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfds[0].revents);

  pfds[0].events = KPOLLRDNORM;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(KPOLLRDNORM, pfds[0].revents);

  pfds[0].events = KPOLLIN | KPOLLOUT;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(KPOLLIN | KPOLLOUT, pfds[0].revents);

  pfds[0].events = KPOLLIN | KPOLLOUT | KPOLLRDNORM;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(KPOLLIN | KPOLLOUT | KPOLLRDNORM, pfds[0].revents);

  char buf[10];
  KEXPECT_EQ(2, vfs_read(fd, buf, 10));


  KTEST_BEGIN("TTY: delayed poll");
  pfds[0].events = KPOLLIN;
  poll_thread_args_t pt_args;
  pt_args.pfds = pfds;
  pt_args.nfds = 1;
  pt_args.timeout = -1;

  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll, &pt_args));
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, 'x');
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, '\n');
  kthread_join(thread);
  KEXPECT_EQ(true, pt_args.finished);
  KEXPECT_EQ(1, pt_args.result);
  KEXPECT_EQ(KPOLLIN, pfds[0].revents);
  KEXPECT_EQ(2, vfs_read(fd, buf, 10));


  KTEST_BEGIN("TTY: delayed poll (masked event, then timeout)");
  pfds[0].events = KPOLLPRI;
  pt_args.timeout = 50;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll, &pt_args));
  scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, 'x');
  scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, '\n');
  scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);
  kthread_join(thread);
  KEXPECT_EQ(true, pt_args.finished);
  KEXPECT_EQ(0, pt_args.result);
  KEXPECT_EQ(2, vfs_read(fd, buf, 10));


  KTEST_BEGIN("TTY: non-sleeping poll (NULL poll_state_t)");
  pfds[0].events = KPOLLIN | KPOLLOUT;
  pfds[1].fd = vfs_dup(fd);
  pfds[1].events = KPOLLIN;

  KEXPECT_EQ(1, vfs_poll(pfds, 2, 0));
  KEXPECT_EQ(KPOLLOUT, pfds[0].revents);
  KEXPECT_EQ(0, pfds[1].revents);

  vfs_close(pfds[1].fd);


  KTEST_BEGIN("TTY: poll() on non-blocking fd");
  int nonblock_fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_NONBLOCK | VFS_O_NOCTTY);
  KEXPECT_GE(nonblock_fd, 0);

  pfds[0].fd = nonblock_fd;
  pfds[0].events = KPOLLIN | KPOLLOUT;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, -1));

  pfds[0].events = KPOLLIN;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));

  pt_args.pfds = pfds;
  pt_args.nfds = 1;
  pt_args.timeout = -1;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll, &pt_args));
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, 'x');
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, '\n');
  kthread_join(thread);
  KEXPECT_EQ(true, pt_args.finished);
  KEXPECT_EQ(1, pt_args.result);
  KEXPECT_EQ(KPOLLIN, pfds[0].revents);
  KEXPECT_EQ(2, vfs_read(fd, buf, 10));

  vfs_close(nonblock_fd);


  KTEST_BEGIN("TTY: poll() in non-canonical mode");
  struct ktermios term;
  ld_get_termios(args.ld, &term);
  const struct ktermios orig_term = term;
  term.c_lflag &= ~ICANON;
  KEXPECT_EQ(0, ld_set_termios(args.ld, TCSANOW, &term));

  pfds[0].fd = fd;
  pfds[0].events = KPOLLIN | KPOLLOUT;
  KEXPECT_EQ(1, vfs_poll(pfds, 1, -1));
  KEXPECT_EQ(KPOLLOUT, pfds[0].revents);

  pfds[0].events = KPOLLIN;
  KEXPECT_EQ(0, vfs_poll(pfds, 1, 0));
  KEXPECT_EQ(0, pfds[0].revents);

  pt_args.pfds = pfds;
  pt_args.nfds = 1;
  pt_args.timeout = -1;

  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll, &pt_args));
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, pt_args.finished);

  ld_provide(args.ld, 'x');
  kthread_join(thread);
  KEXPECT_EQ(true, pt_args.finished);
  KEXPECT_EQ(1, pt_args.result);
  KEXPECT_EQ(KPOLLIN, pfds[0].revents);
  KEXPECT_EQ(1, vfs_read(fd, buf, 10));

  KEXPECT_EQ(0, ld_set_termios(args.ld, TCSANOW, &orig_term));

  // TODO(aoates): test SIGTTOU/non-writable
  // TODO(aoates): destroy TTY/ld while poll is pending

  vfs_close(fd);

  tty_destroy(args.tty);
  ld_destroy(args.ld);
}

static void* provide_thread(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);

  ld_t* ld = (ld_t*)arg;
  ld_provide(ld, 'a');
  ld_provide(ld, 'b');
  ld_provide(ld, '\n');

  ksleep(20);
  sched_disable_preemption();
  return NULL;
}

static void* poll_thread(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(20);  // Sleep a bit longer.

  int fd = *(int*)arg;

  struct apos_pollfd pfd;
  pfd.fd = fd;
  pfd.events = KPOLLIN;

  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 1000));
  KEXPECT_EQ(KPOLLIN, pfd.revents);
  char buf[10];
  KEXPECT_EQ(3, vfs_read(fd, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("ab\n", buf);
  sched_disable_preemption();
  return NULL;
}

static void tty_poll_mt_test(void) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  int sink_counter = 0;
  ld_set_sink(args.ld, &sink, &sink_counter);

  KTEST_BEGIN("TTY: basic poll with second thread (writable but not readable)");
  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", kminor(args.tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_NOCTTY);
  KEXPECT_GE(fd, 0);

  kthread_t thread[2];
  KEXPECT_EQ(0, proc_thread_create(&thread[0], &provide_thread, args.ld));
  KEXPECT_EQ(0, proc_thread_create(&thread[1], &poll_thread, &fd));

  KEXPECT_EQ(NULL, kthread_join(thread[0]));
  KEXPECT_EQ(NULL, kthread_join(thread[1]));

  vfs_close(fd);

  tty_destroy(args.tty);
  ld_destroy(args.ld);
}

void tty_test(void) {
  KTEST_SUITE_BEGIN("TTY tests");

  kpid_t child = proc_fork(&ld_signals_test_runner, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&termios_test_runner, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_nonblock_test();
  tty_poll_test();
  tty_poll_mt_test();
}
