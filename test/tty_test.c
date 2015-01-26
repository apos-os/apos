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
  KEXPECT_EQ(0, ld_set_termios(test_ld, &term));

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
  KEXPECT_EQ(0, ld_set_termios(test_ld, &term));
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

  KEXPECT_EQ(0, ld_set_termios(test_ld, &orig_term));
}

static void ld_signals_test_runner(void* arg) {
  args_t args;
  args.ld = ld_create(5);
  args.tty = tty_create(args.ld);

  pid_t child = proc_fork(&ld_signals_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&ld_signals_isig_flag_test, &args);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(args.tty);
  ld_destroy(args.ld);
}

void tty_test(void) {
  KTEST_SUITE_BEGIN("TTY tests");

  pid_t child = proc_fork(&ld_signals_test_runner, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}
