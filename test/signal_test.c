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

#include <stdint.h>

#include "common/kassert.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"

static void ksigemptyset_test(void) {
  KTEST_BEGIN("ksigemptyset() test");

  sigset_t set;
  KEXPECT_EQ(0, ksigemptyset(&set));
  KEXPECT_EQ(1, ksigisemptyset(&set));

  for (int i = SIGMIN; i <= SIGMAX; ++i) {
    KEXPECT_EQ(0, ksigismember(&set, i));
  }
}

static void ksigfillset_test(void) {
  KTEST_BEGIN("ksigfillset() test");

  sigset_t set;
  KEXPECT_EQ(0, ksigfillset(&set));
  KEXPECT_EQ(0, ksigisemptyset(&set));


  for (int i = SIGMIN; i <= SIGMAX; ++i) {
    KEXPECT_EQ(1, ksigismember(&set, i));
  }
}

static void ksigaddset_test(void) {
  KTEST_BEGIN("ksigaddset() test");

  sigset_t set;
  ksigemptyset(&set);

  KEXPECT_EQ(0, ksigaddset(&set, SIGABRT));
  KEXPECT_EQ(0, ksigisemptyset(&set));

  KEXPECT_EQ(1, ksigismember(&set, SIGABRT));
  KEXPECT_EQ(0, ksigismember(&set, SIGALRM));

  KTEST_BEGIN("ksigaddset() invalid signum test");
  sigset_t old_set = set;
  KEXPECT_EQ(-EINVAL, ksigaddset(&set, SIGNULL));
  KEXPECT_EQ(-EINVAL, ksigaddset(&set, -1));
  KEXPECT_EQ(-EINVAL, ksigaddset(&set, SIGMAX + 1));
  KEXPECT_EQ(old_set, set);
}

static void ksigdelset_test(void) {
  KTEST_BEGIN("ksigdelset() test");

  sigset_t set;
  ksigfillset(&set);

  KEXPECT_EQ(0, ksigdelset(&set, SIGABRT));

  KEXPECT_EQ(0, ksigismember(&set, SIGABRT));
  KEXPECT_EQ(1, ksigismember(&set, SIGALRM));

  KTEST_BEGIN("ksigdelset() invalid signum test");
  sigset_t old_set = set;
  KEXPECT_EQ(-EINVAL, ksigdelset(&set, SIGNULL));
  KEXPECT_EQ(-EINVAL, ksigdelset(&set, -1));
  KEXPECT_EQ(-EINVAL, ksigdelset(&set, SIGMAX + 1));
  KEXPECT_EQ(old_set, set);
}

static void ksigismember_test(void) {
  KTEST_BEGIN("ksigismember() invalid signum test");

  sigset_t set;
  KEXPECT_EQ(-EINVAL, ksigismember(&set, SIGNULL));
  KEXPECT_EQ(-EINVAL, ksigismember(&set, -1));
  KEXPECT_EQ(-EINVAL, ksigismember(&set, SIGMAX + 1));
}

static void kill_test(void) {
  const pid_t my_pid = proc_current()->id;

  KTEST_BEGIN("proc_kill() invalid pid test");
  KEXPECT_EQ(-EINVAL, proc_kill(0, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(-10, SIGABRT));
  // TODO(aoates): figure out a better way to generate a guaranteed-unused PID.
  KEXPECT_EQ(-ESRCH, proc_kill(100, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(PROC_MAX_PROCS + 10, SIGABRT));

  // TODO(aoates): test with a zombie process.

  KTEST_BEGIN("proc_kill() invalid signal test");
  KEXPECT_EQ(-EINVAL, proc_kill(my_pid, -1));
  KEXPECT_EQ(-EINVAL, proc_kill(my_pid, SIGMAX + 1));

  KTEST_BEGIN("proc_kill() SIGNULL test");
  KEXPECT_EQ(0, proc_kill(my_pid, 0));
  KEXPECT_EQ(-ESRCH, proc_kill(PROC_MAX_PROCS + 10, 0));

  // TODO(aoates): test the actual kill functionality.
}

static void sighandler(int signum) {
  die("This should never be run");
}

static void sigaction_test(void) {
  sigaction_t dfl_action;
  dfl_action.sa_handler = SIG_DFL;
  dfl_action.sa_flags = 0;
  ksigemptyset(&dfl_action.sa_mask);

  sigaction_t ign_action = dfl_action;
  ign_action.sa_handler = SIG_IGN;

  sigaction_t custom_action = dfl_action;
  custom_action.sa_handler = &sighandler;

  sigaction_t garbage_action;
  kmemset(&garbage_action, 0xAB, sizeof(sigaction_t));

  sigaction_t oact;

  KTEST_BEGIN("proc_sigaction(): invalid signum");
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGNULL, 0x0, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGMIN - 1, 0x0, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGMAX + 1, 0x0, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(-5, 0x0, 0x0));

  // POSIX seems to indicate that setting invalid flags should succeed.
  KTEST_BEGIN("proc_sigaction(): invalid flags");
  sigaction_t act = dfl_action;
  act.sa_flags = 0x12345;
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &act, 0x0));

  // Ensure we get back the same (invalid) flags when we read.
  oact = garbage_action;
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, 0x0, &oact));
  KEXPECT_EQ(0x12345, oact.sa_flags);

  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &dfl_action, 0x0));


  KTEST_BEGIN("proc_sigaction(): setting SIGKILL/SIGSTOP");
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGKILL, &dfl_action, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGKILL, &dfl_action, &oact));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGSTOP, &dfl_action, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGSTOP, &dfl_action, &oact));

  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGKILL, &ign_action, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGSTOP, &ign_action, 0x0));

  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGKILL, &custom_action, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(SIGSTOP, &custom_action, 0x0));


  KTEST_BEGIN("proc_sigaction(): getting SIGKILL/SIGSTOP");
  KEXPECT_EQ(0, proc_sigaction(SIGKILL, 0x0, 0x0));
  KEXPECT_EQ(0, proc_sigaction(SIGSTOP, 0x0, 0x0));

  oact = garbage_action;
  KEXPECT_EQ(0, proc_sigaction(SIGKILL, 0x0, &oact));
  KEXPECT_EQ(SIG_DFL, oact.sa_handler);

  oact = garbage_action;
  KEXPECT_EQ(0, proc_sigaction(SIGSTOP, 0x0, &oact));
  KEXPECT_EQ(SIG_DFL, oact.sa_handler);


  // As required by POSIX, including SIGKILL and SIGSTOP in sa_mask for another
  // signal should succeed, though it won't actually be masked.
  KTEST_BEGIN("proc_sigaction(): SIGKILL/SIGSTOP in sa_mask");

  act = dfl_action;
  ksigaddset(&act.sa_mask, SIGKILL);
  ksigaddset(&act.sa_mask, SIGSTOP);
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &act, 0x0));

  oact = garbage_action;
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, 0x0, &oact));

  KEXPECT_EQ(1, ksigismember(&oact.sa_mask, SIGKILL));
  KEXPECT_EQ(1, ksigismember(&oact.sa_mask, SIGSTOP));

  KTEST_BEGIN("proc_sigaction(): set and get simultaneously");
  // Set up a new signal handler, then reset it and do a get at the same time,
  // and verify that the old signal handler is returned.
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &ign_action, 0x0));

  // Do a simultaneous get+set and verify the results.
  act = dfl_action;
  ksigaddset(&act.sa_mask, SIGUSR2);

  oact = garbage_action;
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &act, &oact));

  KEXPECT_EQ(SIG_IGN, oact.sa_handler);
  KEXPECT_EQ(ign_action.sa_mask, oact.sa_mask);

  // The previous get+set should have set the handler properly, so check that.
  oact = garbage_action;
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, 0x0, &oact));
  KEXPECT_EQ(SIG_DFL, oact.sa_handler);
  KEXPECT_EQ(1, ksigismember(&oact.sa_mask, SIGUSR2));

  // And finally restore the default.
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &dfl_action, 0x0));

  // TODO(aoates): test actual signal handling, which requires a better way to
  // do user-space tests.
}

static void signal_allowed_test(void) {
  process_t A, B, A_default, B_default;

  A_default.ruid = 1001; A_default.rgid = 2001;
  A_default.euid = 1002; A_default.egid = 2002;
  A_default.suid = 1003; A_default.sgid = 2003;
  B_default.ruid = 3001; B_default.rgid = 4001;
  B_default.euid = 3002; B_default.egid = 4002;
  B_default.suid = 3003; B_default.sgid = 4003;

  KTEST_BEGIN("proc_signal_allowed(): root can send any signal");
  A = A_default; B = B_default;
  A.euid = SUPERUSER_UID;

  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGTERM));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGSTOP));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));

  KEXPECT_EQ(0, proc_signal_allowed(&B, &A, SIGTERM));
  KEXPECT_EQ(0, proc_signal_allowed(&B, &A, SIGKILL));
  KEXPECT_EQ(0, proc_signal_allowed(&B, &A, SIGSTOP));
  KEXPECT_EQ(0, proc_signal_allowed(&B, &A, SIGCONT));

  KTEST_BEGIN("proc_signal_allowed(): allowed if ruid matches ruid");
  A = A_default; B = B_default;
  A.ruid = B.ruid;

  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));

  KTEST_BEGIN("proc_signal_allowed(): allowed if euid matches ruid");
  A = A_default; B = B_default;
  A.euid = B.ruid;

  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));

  KTEST_BEGIN("proc_signal_allowed(): allowed if ruid matches suid");
  A = A_default; B = B_default;
  A.ruid = B.suid;

  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));

  KTEST_BEGIN("proc_signal_allowed(): allowed if euid matches suid");
  A = A_default; B = B_default;
  A.euid = B.suid;

  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));

  KTEST_BEGIN("proc_signal_allowed(): NOT allowed if nothing matches");
  A = A_default; B = B_default;
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGCONT));

  KTEST_BEGIN("proc_signal_allowed(): NOT allowed even if suid matches ruid");
  A = A_default; B = B_default;
  A.suid = B.ruid;
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGKILL));

  KTEST_BEGIN("proc_signal_allowed(): NOT allowed even if suid matches euid");
  A = A_default; B = B_default;
  A.suid = B.euid;
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGKILL));

  KTEST_BEGIN("proc_signal_allowed(): NOT allowed even if suid matches suid");
  A = A_default; B = B_default;
  A.suid = B.suid;
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGKILL));

  KTEST_BEGIN("proc_signal_allowed(): NOT allowed even if gids match");
  A = A_default; B = B_default;
  A.rgid = B.rgid;
  A.egid = B.egid;
  A.sgid = B.sgid;

  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGKILL));
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGCONT));
}

// Child process that sleeps then exits, to let us test if signals were
// delivered or not.
static void signal_child_func(void* arg) {
  ksleep(10);
  proc_exit(ksigismember(&proc_current()->pending_signals, SIGKILL));
}

static void signal_setuid_then_kill_func(void* arg) {
  proc_current()->ruid = 100;
  proc_current()->euid = 100;
  proc_current()->suid = 100;

  int child_pid = proc_fork(&signal_child_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_get(child_pid)->ruid = 101;
  proc_get(child_pid)->euid = 101;
  proc_get(child_pid)->suid = 101;

  KEXPECT_EQ(-EPERM, proc_kill(child_pid, SIGKILL));
  int exit_code;
  KEXPECT_EQ(child_pid, proc_wait(&exit_code));
  KEXPECT_EQ(0, exit_code);  // Should not have received signal.
}

static void signal_permission_test(void) {
  KTEST_BEGIN("proc_kill(): root can signal any process");

  int child_pid = proc_fork(&signal_child_func, (void*)100);
  KEXPECT_GE(child_pid, 0);

  proc_get(child_pid)->ruid = 101;
  proc_get(child_pid)->euid = 101;
  proc_get(child_pid)->suid = 101;

  KEXPECT_EQ(0, proc_kill(child_pid, SIGKILL));
  int exit_code;
  KEXPECT_EQ(child_pid, proc_wait(&exit_code));
  KEXPECT_EQ(1, exit_code);  // Should have received signal.

  KTEST_BEGIN("proc_kill(): different user can't signal process");
  child_pid = proc_fork(&signal_setuid_then_kill_func, 0x0);
  KEXPECT_GE(child_pid, 0);
  KEXPECT_EQ(child_pid, proc_wait(0x0));
}

void signal_test(void) {
  KTEST_SUITE_BEGIN("signals");

  // Save the current signal handlers to restore at the end.
  sigaction_t saved_handlers[SIGMAX + 1];
  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    KASSERT(proc_sigaction(signum, 0x0, &saved_handlers[signum]) == 0);
  }

  ksigemptyset_test();
  ksigfillset_test();
  ksigaddset_test();
  ksigdelset_test();
  ksigismember_test();

  kill_test();
  sigaction_test();

  signal_allowed_test();
  signal_permission_test();

  // Restore all the signal handlers in case any of the tests didn't clean up.
  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    if (signum != SIGSTOP && signum != SIGKILL) {
      KASSERT(proc_sigaction(signum, &saved_handlers[signum], 0x0) == 0);
    }
  }
}
