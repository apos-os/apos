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
#include "proc/group.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"

// Helper to determine if a signal is pending or assigned.
static int is_signal_pending(const process_t* proc, int signum) {
  sigset_t pending = proc_pending_signals(proc);
  return ksigismember(&pending, signum);
}

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
  // TODO(aoates): figure out a better way to generate a guaranteed-unused PID.
  KEXPECT_EQ(-ESRCH, proc_kill(100, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(-100, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(PROC_MAX_PROCS + 10, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(-(PROC_MAX_PROCS + 10), SIGABRT));

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
  proc_exit(is_signal_pending(proc_current(), SIGKILL));
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

// Helper that sets up a process group with several processes.  |okA| and |okB|
// will be set to pids in the new group that can receive signals from the
// current process; |bad| will be set to a pid in the current group that cannot.
static void create_process_group(pid_t* okA, pid_t* okB, pid_t* bad) {
  *okA = proc_fork(&signal_child_func, 0x0);
  *okB = proc_fork(&signal_child_func, 0x0);
  *bad = proc_fork(&signal_child_func, 0x0);

  KEXPECT_EQ(0, setpgid(*okA, *okA));
  KEXPECT_EQ(0, setpgid(*okB, *okA));
  KEXPECT_EQ(0, setpgid(*bad, *okA));

  proc_get(*bad)->ruid = proc_get(*bad)->euid = proc_get(*bad)->suid = 1000;
}

// Create a process group then send SIGKILL to it.  |arg| is a bitfield.  If bit
// 1 is set, then the current process is included in the process group (and
// expected to receive the SIGKILL as well).  If bit 2 is set, then the signal
// is sent to pgid 0 (i.e. the current process group).
static void create_group_then_kill(void* arg) {
  uint32_t flags = (uint32_t)arg;

  // Ensure we're not the superuser.
  KEXPECT_EQ(0, setuid(500));

  pid_t okA, okB, bad;
  create_process_group(&okA, &okB, &bad);

  if (flags & 0x1) {
    KEXPECT_EQ(0, setpgid(0, okA));
  }

  if (flags & 0x2) {
    KEXPECT_EQ(0, proc_kill(0, SIGKILL));
    KEXPECT_EQ(0, proc_kill(0, SIGNULL));  // Try SIGNULL too, for kicks.
  } else {
    KEXPECT_EQ(0, proc_kill(-okA, SIGKILL));
    KEXPECT_EQ(0, proc_kill(-okA, SIGNULL));  // Try SIGNULL too, for kicks.
  }

  // We should have received the signal if we're in the group.
  int got_signal = is_signal_pending(proc_current(), SIGKILL);
  if (flags & 0x1) {
    KEXPECT_EQ(1, got_signal);
  } else {
    KEXPECT_EQ(0, got_signal);
  }

  // Either way, okA and okB should have gotten it as well, but not bad.
  for (int i = 0; i < 3; ++i) {
    int status;
    int child = proc_wait(&status);
    if (child == okA || child == okB) {
      KEXPECT_EQ(1, status);
    } else {
      KEXPECT_EQ(0, status);
    }
  }
}

static void cannot_signal_any_process_in_group(void* arg) {
  KTEST_BEGIN("proc_kill(): cannot send signal to any process in group");
  // Ensure we're not the superuser.
  KEXPECT_EQ(0, setuid(500));

  pid_t okA, okB, bad;
  create_process_group(&okA, &okB, &bad);

  KEXPECT_EQ(0, setpgid(bad, bad));

  KEXPECT_EQ(-EPERM, proc_kill(-bad, SIGKILL));

  KTEST_BEGIN("proc_kill(): invalid signal to process group");
  KEXPECT_EQ(0, setpgid(0, okA));
  KEXPECT_EQ(-EINVAL, proc_kill(0, -1));
  KEXPECT_EQ(-EINVAL, proc_kill(0, SIGMAX + 1));
  KEXPECT_EQ(-EINVAL, proc_kill(-okA, SIGMAX + 1));
  KEXPECT_EQ(-EINVAL, proc_kill(-bad, SIGMAX + 1));

  // No-one should have received any signals.
  for (int i = 0; i < 3; ++i) {
    int status;
    proc_wait(&status);
    KEXPECT_EQ(0, status);
  }
}

static void signal_send_to_pgroup_test(void) {
  KTEST_BEGIN("proc_kill(): pid == -pgid sends to process group "
              "(not including current process)");
  int child = proc_fork(&create_group_then_kill, 0x0);
  KEXPECT_EQ(child, proc_wait(0x0));

  KTEST_BEGIN("proc_kill(): pid == -pgid sends to process group "
              "(including current process)");
  child = proc_fork(&create_group_then_kill, (void*)0x1);
  KEXPECT_EQ(child, proc_wait(0x0));

  KTEST_BEGIN("proc_kill(): pid == 0 sends to current process group");
  child = proc_fork(&create_group_then_kill, (void*)0x3);
  KEXPECT_EQ(child, proc_wait(0x0));

  child = proc_fork(&cannot_signal_any_process_in_group, 0x0);
  KEXPECT_EQ(child, proc_wait(0x0));
}

static void send_all_allowed_func(void* arg) {
  KEXPECT_EQ(0, setuid((uid_t)arg));
  KEXPECT_EQ(0, proc_kill(-1, SIGKILL));
  proc_exit(is_signal_pending(proc_current(), SIGKILL));
}

static void signal_send_to_all_allowed_test(void) {
  KTEST_BEGIN("proc_kill(): pid == -1 sends to all allowed processes");

  int children[4];
  for (int i = 0; i < 3; ++i) {
    children[i] = proc_fork(&signal_child_func, 0x0);
  }

  // Make children 1 and 3 killable by child 4.
  proc_get(children[0])->ruid = 800;
  proc_get(children[1])->ruid = 600;
  proc_get(children[2])->ruid = 800;
  children[3] = proc_fork(&send_all_allowed_func, (void*)800);

  int statuses[4];
  for (int i = 0; i < 4; ++i) {
    int status;
    int child = proc_wait(&status);
    if (child == children[0]) statuses[0] = status;
    else if (child == children[1]) statuses[1] = status;
    else if (child == children[2]) statuses[2] = status;
    else if (child == children[3]) statuses[3] = status;
    else die("unknown child");
  }

  KEXPECT_EQ(1, statuses[0]);
  KEXPECT_EQ(0, statuses[1]);
  KEXPECT_EQ(1, statuses[2]);
  KEXPECT_EQ(1, statuses[3]);

  KTEST_BEGIN("proc_kill(): pid == -1 skips processes 0 and 1");
  int child = proc_fork(&send_all_allowed_func, (void*)0);
  KEXPECT_EQ(child, proc_wait(0x0));

  // The signal shouldn't have been sent to processes 0 or 1.
  if (proc_get(0))
    KEXPECT_EQ(0, is_signal_pending(proc_get(0), SIGKILL));
  if (proc_get(1))
    KEXPECT_EQ(0, is_signal_pending(proc_get(1), SIGKILL));

  // TODO(aoates): is there any scenario in which a process wouldn't be able to
  // send a signal to itself, and therefore proc_kill(-1, X) would return
  // -EPERM?
}

struct victim_args {
  int signum;
  struct sigaction action;
  kthread_queue_t queue;
  bool interruptable;
  sigset_t mask;
};

static void interrupted_handler(int signum) {
  // This never actually runs.
}

static void signal_interrupt_victim(void* arg) {
  struct victim_args* args = (struct victim_args*)arg;

  // TODO(aoates): use the appropriate syscall when available.
  proc_current()->thread->signal_mask = args->mask;

  int result = proc_sigaction(args->signum, &args->action, NULL);
  if (result) {
    klogfm(KL_TEST, WARNING, "sigaction() failed: %s\n",
           errorname(-result));
    proc_exit(-1);
  }

  result = 0;
  if (args->interruptable) {
    result = scheduler_wait_on_interruptable(&args->queue);
  } else {
    scheduler_wait_on(&args->queue);
  }
  proc_exit(result);
}

static void do_interrupt_test(struct victim_args args,
                              bool expect_interrupted) {
  int child = proc_fork(&signal_interrupt_victim, &args);
  scheduler_yield();
  proc_kill(child, args.signum);

  if (expect_interrupted) {
    KEXPECT_EQ(1, kthread_queue_empty(&args.queue));
  } else {
    KEXPECT_EQ(0, kthread_queue_empty(&args.queue));
  }
  scheduler_wake_all(&args.queue);

  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  if (expect_interrupted) {
    KEXPECT_EQ(1, status);
  } else {
    KEXPECT_EQ(0, status);
  }
}

static void signal_interrupt_thread_test(void) {
  struct victim_args default_args;
  default_args.action.sa_handler = &interrupted_handler;
  ksigemptyset(&default_args.action.sa_mask);
  default_args.action.sa_flags = 0;
  default_args.signum = SIGUSR1;
  default_args.interruptable = true;
  ksigemptyset(&default_args.mask);
  kthread_queue_init(&default_args.queue);

  {
    KTEST_BEGIN("signal interruptable sleep: basic test");
    struct victim_args args = default_args;
    do_interrupt_test(args, true);
  }

  {
    KTEST_BEGIN("signal non-interruptable sleep");
    struct victim_args args = default_args;
    args.interruptable = false;
    do_interrupt_test(args, false);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: sigaction is SIG_IGN");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_IGN;
    do_interrupt_test(args, false);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is ignored by default");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    args.signum = SIGURG;

    do_interrupt_test(args, false);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is default TERM");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    args.signum = SIGUSR1;

    do_interrupt_test(args, true);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is default TERM_AND_CORE");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    args.signum = SIGSEGV;

    do_interrupt_test(args, true);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is default STOP");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    args.signum = SIGTSTP;

    do_interrupt_test(args, true);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is default CONTINUE");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    args.signum = SIGCONT;

    do_interrupt_test(args, true);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is masked");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    ksigaddset(&args.mask, SIGUSR1);

    do_interrupt_test(args, false);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is masked "
                "(force assignment to thread)");
    struct victim_args args = default_args;
    args.action.sa_handler = SIG_DFL;
    ksigaddset(&args.mask, SIGUSR1);

    int child = proc_fork(&signal_interrupt_victim, &args);
    scheduler_yield();
    proc_force_signal_on_thread(proc_get(child), proc_get(child)->thread,
                                args.signum);

    KEXPECT_EQ(0, kthread_queue_empty(&args.queue));
    scheduler_wake_all(&args.queue);

    int status;
    KEXPECT_EQ(child, proc_wait(&status));
    KEXPECT_EQ(0, status);
  }

  {
    KTEST_BEGIN("signal interruptable sleep: signal is unmasked "
                "(force assignment to thread)");
    struct victim_args args = default_args;

    int child = proc_fork(&signal_interrupt_victim, &args);
    scheduler_yield();
    proc_force_signal_on_thread(proc_get(child), proc_get(child)->thread,
                                args.signum);

    KEXPECT_EQ(1, kthread_queue_empty(&args.queue));
    scheduler_wake_all(&args.queue);

    int status;
    KEXPECT_EQ(child, proc_wait(&status));
    KEXPECT_EQ(1, status);
  }

  // TODO(aoates): tests for various sa_flags when they're implemented.
}

static void ksleep_interrupted_func(void* arg) {
  proc_exit(ksleep((int)arg));
}

static void ksleep_interrupted_test(void) {
  KTEST_BEGIN("ksleep(): interrupted by signal test");

  int child = proc_fork(&ksleep_interrupted_func, (void*)200);

  const int start_time = get_time_ms();
  ksleep(20);

  KEXPECT_EQ(0, proc_kill(child, SIGALRM));

  int exit_status = 0;
  KEXPECT_EQ(child, proc_wait(&exit_status));
  const int end_time = get_time_ms();

  KEXPECT_GE(end_time - start_time, 20);
  KEXPECT_LE(end_time - start_time, 40);
  KEXPECT_GE(exit_status, 160);
  KEXPECT_LE(exit_status, 180);
}

static void sigprocmask_test(void) {
  // (cheating)
  const sigset_t orig_mask = kthread_current_thread()->signal_mask;

  KTEST_BEGIN("sigprocmask(): block signals");
  sigset_t mask, mask2;
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &mask));
  KEXPECT_EQ(orig_mask, mask);
  KEXPECT_EQ(0, ksigismember(&mask, SIGUSR1));  // Make sure our test will work.

  ksigaddset(&mask, SIGUSR1);
  ksigaddset(&mask, SIGPIPE);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGUSR1));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGALRM));
  KEXPECT_EQ(mask, mask2);

  // Try adding another one.
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGALRM);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGUSR1));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGALRM));

  // Blocking same signals again should be a no-op.
  ksigemptyset(&mask2);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGUSR1));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGALRM));

  KTEST_BEGIN("sigprocmask(): unblock signals");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGPIPE);
  ksigaddset(&mask, SIGUSR2);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &mask, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGUSR1));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGALRM));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGUSR2));

  KTEST_BEGIN("sigprocmask(): setmask");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGPIPE);
  ksigaddset(&mask, SIGSYS);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &mask2));
  KEXPECT_EQ(mask, mask2);

  KTEST_BEGIN("sigprocmask(): SIG_BLOCK with oset");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGPIPE);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));
  ksigaddset(&mask, SIGSYS);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGSYS));


  KTEST_BEGIN("sigprocmask(): SIG_UNBLOCK with oset");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGPIPE);
  ksigaddset(&mask, SIGSYS);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));
  ksigdelset(&mask, SIGSYS);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &mask, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGSYS));


  KTEST_BEGIN("sigprocmask(): SIG_SETMASK with oset");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGPIPE);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));
  ksigaddset(&mask, SIGSYS);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, &mask2));
  KEXPECT_EQ(1, ksigismember(&mask2, SIGPIPE));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGSYS));


  KTEST_BEGIN("sigprocmask(): ignore how if set is NULL");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  ksigaddset(&mask, SIGPIPE);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));

  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, NULL, &mask2));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, NULL, &mask2));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, NULL, &mask2));
  KEXPECT_EQ(0, proc_sigprocmask(-2, NULL, &mask2));
  KEXPECT_EQ(0, proc_sigprocmask(1000, NULL, &mask2));


  KTEST_BEGIN("sigprocmask(): block unblockable signals");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));

  ksigaddset(&mask, SIGUSR1);
  ksigaddset(&mask, SIGKILL);
  ksigaddset(&mask, SIGSTOP);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &mask, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, NULL, &mask2));

  KEXPECT_EQ(1, ksigismember(&mask2, SIGUSR1));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGKILL));
  KEXPECT_EQ(0, ksigismember(&mask2, SIGSTOP));


  KTEST_BEGIN("sigprocmask(): invalid how arg");
  ksigemptyset(&mask); ksigemptyset(&mask2);
  KEXPECT_EQ(-EINVAL, proc_sigprocmask(-1, &mask, NULL));
  KEXPECT_EQ(-EINVAL, proc_sigprocmask(100, &mask, NULL));
  KEXPECT_EQ(-EINVAL, proc_sigprocmask(-1, &mask, &mask2));
  KEXPECT_EQ(-EINVAL, proc_sigprocmask(100, &mask, &mask2));

  kthread_current_thread()->signal_mask = orig_mask;
}

void signal_test(void) {
  KTEST_SUITE_BEGIN("signals");

  // Save the current signal handlers to restore at the end.
  sigaction_t saved_handlers[SIGMAX + 1];
  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    KASSERT(proc_sigaction(signum, 0x0, &saved_handlers[signum]) == 0);
  }
  sigset_t saved_pending_signals = proc_current()->pending_signals;
  // TODO(aoates): do we want to save/restore the signal mask as well?

  ksigemptyset_test();
  ksigfillset_test();
  ksigaddset_test();
  ksigdelset_test();
  ksigismember_test();

  kill_test();
  sigaction_test();

  signal_allowed_test();
  signal_permission_test();

  signal_send_to_pgroup_test();
  signal_send_to_all_allowed_test();

  signal_interrupt_thread_test();
  ksleep_interrupted_test();
  sigprocmask_test();

  // Restore all the signal handlers in case any of the tests didn't clean up.
  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    if (signum != SIGSTOP && signum != SIGKILL) {
      KASSERT(proc_sigaction(signum, &saved_handlers[signum], 0x0) == 0);
    }
  }
  proc_current()->pending_signals = saved_pending_signals;
}
