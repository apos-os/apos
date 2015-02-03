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
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/tcgroup.h"
#include "proc/wait.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "user/include/apos/termios.h"
#include "vfs/vfs.h"

static void do_nothing(void* arg) {}

static int sig_is_pending(process_t* proc, int sig) {
  sigset_t pending = proc_pending_signals(proc);
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
  const pid_t childA = proc_fork(&do_nothing, NULL);
  const pid_t childB = proc_fork(&do_nothing, NULL);
  const pid_t childC = proc_fork(&do_nothing, NULL);
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
  ksprintf(tty_name, "/dev/tty%d", minor(test_tty));
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
  sigset_t sigset, old_sigmask;
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

  struct termios term;
  ld_get_termios(test_ld, &term);
  const struct termios orig_term = term;

  KTEST_BEGIN("TTY: ctrl-C/SIGINT disabled if ISIG isn't set");
  term.c_lflag &= ~ISIG;
  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &term));

  KEXPECT_EQ(proc_current()->id, proc_setsid());
  int sink_counter = 0;
  ld_set_sink(test_ld, &sink, &sink_counter);

  const pid_t childA = proc_fork(&do_nothing, NULL);
  const pid_t childB = proc_fork(&do_nothing, NULL);
  const pid_t childC = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(childB, 0));
  KEXPECT_EQ(0, setpgid(childC, childB));

  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", minor(test_tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  sigset_t sigset, old_sigmask;
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
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10));
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
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10));
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
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10));
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
  KEXPECT_EQ(1, ld_read(test_ld, buf, 10));
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

  struct termios term;
  ld_get_termios(test_ld, &term);
  const struct termios orig_term = term;

  KTEST_BEGIN("ld: change INTR character");
  KEXPECT_EQ(proc_current()->id, proc_setsid());
  int sink_counter = 0;
  ld_set_sink(test_ld, &sink, &sink_counter);

  char tty_name[20];
  ksprintf(tty_name, "/dev/tty%d", minor(test_tty));
  int fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(fd, 0);

  sigset_t sigset, old_sigmask;
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
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10));
  KEXPECT_STREQ("a\x03" "b", buf);

  ld_provide(test_ld, 'x');
  ld_provide(test_ld, 'p');
  KEXPECT_EQ(0, ld_read_async(test_ld, buf, 10));
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
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10));
  KEXPECT_STREQ("a\x1c" "b", buf);

  ld_provide(test_ld, 'x');
  ld_provide(test_ld, 'q');
  KEXPECT_EQ(0, ld_read_async(test_ld, buf, 10));
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
  KEXPECT_EQ(3, ld_read(test_ld, buf, 10));
  KEXPECT_STREQ("a\x1a" "b", buf);

  ld_provide(test_ld, 'x');
  ld_provide(test_ld, 'q');
  KEXPECT_EQ(0, ld_read_async(test_ld, buf, 10));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTSTP));


  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_sigmask, NULL));

  KEXPECT_EQ(0, ld_set_termios(test_ld, TCSANOW, &orig_term));
}

static void ld_signals_test_runner(void* arg) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  pid_t child = proc_fork(&ld_signals_test, &args);
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
  ksprintf(tty_name, "/dev/tty%d", minor(args->tty));

  KTEST_BEGIN("tty: tcgetattr() defaults");
  const int tty_fd = vfs_open(tty_name, VFS_O_RDWR | VFS_O_NOCTTY);
  KEXPECT_GE(tty_fd, 0);
  const int other_fd =
      vfs_open("_tty_test_file", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(other_fd, 0);

  struct termios t;
  kmemset(&t, 0xFF, sizeof(struct termios));
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
  KEXPECT_EQ(0, ld_read_async(args->ld, buf, 10));


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
  KEXPECT_EQ(0, ld_read_async(args->ld, buf, 10));


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
  ksprintf(tty_name, "/dev/tty%d", minor(args->tty));

  KTEST_BEGIN("tty: setup for background pgroup tests");
  sigset_t kSigTtouSet;
  ksigemptyset(&kSigTtouSet);
  ksigaddset(&kSigTtouSet, SIGTTOU);

  KEXPECT_EQ(proc_current()->id, proc_setsid());

  sigset_t ttou_mask;
  ksigemptyset(&ttou_mask);
  ksigaddset(&ttou_mask, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &ttou_mask, NULL));

  const int tty_fd = vfs_open(tty_name, VFS_O_RDWR);
  KEXPECT_GE(tty_fd, 0);

  pid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(child, child));
  KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, child));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &ttou_mask, NULL));

  pid_t child_in_grp = proc_fork(&do_nothing, NULL);


  KTEST_BEGIN("tty: tcgetattr() from background pgroup");
  struct termios t;
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

  char buf[10];
  KEXPECT_EQ(1, ld_read_async(args->ld, buf, 10));

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
  ksprintf(tty_name, "/dev/tty%d", minor(args->tty));

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

  pid_t child = proc_fork(&termios_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&termios_bg_pgrp_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&tty_truncate_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(args.tty);
  ld_destroy(args.ld);
}

void tty_test(void) {
  KTEST_SUITE_BEGIN("TTY tests");

  pid_t child = proc_fork(&ld_signals_test_runner, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&termios_test_runner, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}
