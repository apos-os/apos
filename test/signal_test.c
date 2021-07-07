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
#include "vfs/pipe.h"
#include "vfs/vfs.h"

// TODO(aoates): remove these helpers when proper multi-thread support is in.
static kthread_data_t* get_proc_thread(process_t* proc) {
  KASSERT_DBG(proc->threads.head == proc->threads.tail);
  return container_of(proc->threads.head, kthread_data_t, proc_threads_link);
}

static kthread_data_t* proc_current_thread(void) {
  return get_proc_thread(proc_current());
}

// Helper to determine if a signal is pending or assigned.
static int is_signal_pending(const process_t* proc, int signum) {
  ksigset_t pending = proc_pending_signals(proc);
  return ksigismember(&pending, signum);
}

static void ksigemptyset_test(void) {
  KTEST_BEGIN("ksigemptyset() test");

  ksigset_t set;
  KEXPECT_EQ(0, ksigemptyset(&set));
  KEXPECT_EQ(1, ksigisemptyset(set));

  for (int i = APOS_SIGMIN; i <= APOS_SIGMAX; ++i) {
    KEXPECT_EQ(0, ksigismember(&set, i));
  }
}

static void ksigfillset_test(void) {
  KTEST_BEGIN("ksigfillset() test");

  ksigset_t set;
  KEXPECT_EQ(0, ksigfillset(&set));
  KEXPECT_EQ(0, ksigisemptyset(set));


  for (int i = APOS_SIGMIN; i <= APOS_SIGMAX; ++i) {
    KEXPECT_EQ(1, ksigismember(&set, i));
  }
}

static void ksigaddset_test(void) {
  KTEST_BEGIN("ksigaddset() test");

  ksigset_t set;
  ksigemptyset(&set);

  KEXPECT_EQ(0, ksigaddset(&set, SIGABRT));
  KEXPECT_EQ(0, ksigisemptyset(set));

  KEXPECT_EQ(1, ksigismember(&set, SIGABRT));
  KEXPECT_EQ(0, ksigismember(&set, SIGALRM));

  KTEST_BEGIN("ksigaddset() invalid signum test");
  ksigset_t old_set = set;
  KEXPECT_EQ(-EINVAL, ksigaddset(&set, APOS_SIGNULL));
  KEXPECT_EQ(-EINVAL, ksigaddset(&set, -1));
  KEXPECT_EQ(-EINVAL, ksigaddset(&set, APOS_SIGMAX + 1));
  KEXPECT_EQ(old_set, set);
}

static void ksigdelset_test(void) {
  KTEST_BEGIN("ksigdelset() test");

  ksigset_t set;
  ksigfillset(&set);

  KEXPECT_EQ(0, ksigdelset(&set, SIGABRT));

  KEXPECT_EQ(0, ksigismember(&set, SIGABRT));
  KEXPECT_EQ(1, ksigismember(&set, SIGALRM));

  KTEST_BEGIN("ksigdelset() invalid signum test");
  ksigset_t old_set = set;
  KEXPECT_EQ(-EINVAL, ksigdelset(&set, APOS_SIGNULL));
  KEXPECT_EQ(-EINVAL, ksigdelset(&set, -1));
  KEXPECT_EQ(-EINVAL, ksigdelset(&set, APOS_SIGMAX + 1));
  KEXPECT_EQ(old_set, set);
}

static void ksigismember_test(void) {
  KTEST_BEGIN("ksigismember() invalid signum test");

  ksigset_t set;
  KEXPECT_EQ(-EINVAL, ksigismember(&set, APOS_SIGNULL));
  KEXPECT_EQ(-EINVAL, ksigismember(&set, -1));
  KEXPECT_EQ(-EINVAL, ksigismember(&set, APOS_SIGMAX + 1));
}

static void kill_test(void) {
  const kpid_t my_pid = proc_current()->id;

  KTEST_BEGIN("proc_kill() invalid pid test");
  // TODO(aoates): figure out a better way to generate a guaranteed-unused PID.
  KEXPECT_EQ(-ESRCH, proc_kill(100, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(-100, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(PROC_MAX_PROCS + 10, SIGABRT));
  KEXPECT_EQ(-ESRCH, proc_kill(-(PROC_MAX_PROCS + 10), SIGABRT));

  // TODO(aoates): test with a zombie process.

  KTEST_BEGIN("proc_kill() invalid signal test");
  KEXPECT_EQ(-EINVAL, proc_kill(my_pid, -1));
  KEXPECT_EQ(-EINVAL, proc_kill(my_pid, APOS_SIGMAX + 1));

  KTEST_BEGIN("proc_kill() SIGNULL test");
  KEXPECT_EQ(0, proc_kill(my_pid, 0));
  KEXPECT_EQ(-ESRCH, proc_kill(PROC_MAX_PROCS + 10, 0));

  // TODO(aoates): test the actual kill functionality.
}

static void sighandler(int signum) {
  die("This should never be run");
}

static void sigaction_test(void) {
  ksigaction_t dfl_action;
  dfl_action.sa_handler = SIG_DFL;
  dfl_action.sa_flags = 0;
  ksigemptyset(&dfl_action.sa_mask);

  ksigaction_t ign_action = dfl_action;
  ign_action.sa_handler = SIG_IGN;

  ksigaction_t custom_action = dfl_action;
  custom_action.sa_handler = &sighandler;

  ksigaction_t garbage_action;
  kmemset(&garbage_action, 0xAB, sizeof(ksigaction_t));

  ksigaction_t oact;

  KTEST_BEGIN("proc_sigaction(): invalid signum");
  KEXPECT_EQ(-EINVAL, proc_sigaction(APOS_SIGNULL, 0x0, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(APOS_SIGMIN - 1, 0x0, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(APOS_SIGMAX + 1, 0x0, 0x0));
  KEXPECT_EQ(-EINVAL, proc_sigaction(-5, 0x0, 0x0));

  // POSIX seems to indicate that setting invalid flags should succeed.
  KTEST_BEGIN("proc_sigaction(): invalid flags");
  ksigaction_t act = dfl_action;
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

  A_default.pgroup = B_default.pgroup = proc_current()->pgroup;

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
  KEXPECT_EQ(1, proc_signal_allowed(&B, &A, SIGCONT));

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
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGUSR1));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));

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
  KEXPECT_EQ(0, proc_signal_allowed(&A, &B, SIGUSR1));
  KEXPECT_EQ(1, proc_signal_allowed(&A, &B, SIGCONT));
}

// Child process that sleeps then exits, to let us test if signals were
// delivered or not.
static void signal_child_func(void* arg) {
  ksleep(10);
  proc_exit(is_signal_pending(proc_current(), SIGAPOSTEST));
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
  KEXPECT_EQ(-EPERM, proc_kill(child_pid, SIGAPOSTEST));
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

  KEXPECT_EQ(0, proc_kill(child_pid, SIGAPOSTEST));
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
static void create_process_group(kpid_t* okA, kpid_t* okB, kpid_t* bad) {
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
  unsigned int flags = (intptr_t)arg;

  // Ensure we're not the superuser.
  KEXPECT_EQ(0, setuid(500));

  kpid_t okA, okB, bad;
  create_process_group(&okA, &okB, &bad);

  if (flags & 0x1) {
    KEXPECT_EQ(0, setpgid(0, okA));
  }

  if (flags & 0x2) {
    KEXPECT_EQ(0, proc_kill(0, SIGAPOSTEST));
    KEXPECT_EQ(0, proc_kill(0, APOS_SIGNULL));  // Try SIGNULL too, for kicks.
  } else {
    KEXPECT_EQ(0, proc_kill(-okA, SIGAPOSTEST));
    KEXPECT_EQ(0, proc_kill(-okA, APOS_SIGNULL));  // Try SIGNULL too, for kicks
  }

  // We should have received the signal if we're in the group.
  int got_signal = is_signal_pending(proc_current(), SIGAPOSTEST);
  if (flags & 0x1) {
    KEXPECT_EQ(1, got_signal);
    proc_suppress_signal(proc_current(), SIGAPOSTEST);
  } else {
    KEXPECT_EQ(0, got_signal);
  }

  // Either way, okA and okB should have gotten it as well, but not bad.
  for (int i = 0; i < 3; ++i) {
    int status;
    int child = proc_wait(&status);
    KEXPECT_GE(child, 0);
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

  kpid_t okA, okB, bad;
  create_process_group(&okA, &okB, &bad);

  KEXPECT_EQ(0, setpgid(bad, bad));

  KEXPECT_EQ(-EPERM, proc_kill(-bad, SIGKILL));
  KEXPECT_EQ(-EPERM, proc_kill(-bad, SIGAPOSTEST));

  KTEST_BEGIN("proc_kill(): invalid signal to process group");
  KEXPECT_EQ(0, setpgid(0, okA));
  KEXPECT_EQ(-EINVAL, proc_kill(0, -1));
  KEXPECT_EQ(-EINVAL, proc_kill(0, APOS_SIGMAX + 1));
  KEXPECT_EQ(-EINVAL, proc_kill(-okA, APOS_SIGMAX + 1));
  KEXPECT_EQ(-EINVAL, proc_kill(-bad, APOS_SIGMAX + 1));

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

  KTEST_BEGIN("proc_kill(): pid == -pgid with bad pgid");
  KEXPECT_EQ(-ESRCH, proc_kill(-child, SIGKILL));
  KEXPECT_EQ(-ESRCH, proc_kill(-PROC_MAX_PROCS, SIGKILL));
  KEXPECT_EQ(-ESRCH, proc_kill(-PROC_MAX_PROCS - 1, SIGKILL));
  KEXPECT_EQ(-ESRCH, proc_kill(-1000000, SIGKILL));
}

static void send_all_allowed_func(void* arg) {
  KEXPECT_EQ(0, setuid((intptr_t)arg));
  KEXPECT_EQ(0, proc_kill(-1, SIGAPOSTEST));
  proc_exit(is_signal_pending(proc_current(), SIGAPOSTEST));
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
  kpid_t wait_result;
  do {
    wait_result = proc_wait(NULL);
    proc_suppress_signal(proc_current(), SIGAPOSTEST);
  } while (wait_result == -EINTR);
  KEXPECT_EQ(child, wait_result);

  // The signal shouldn't have been sent to processes 0 or 1.
  if (proc_get(0))
    KEXPECT_EQ(0, is_signal_pending(proc_get(0), SIGAPOSTEST));
  if (proc_get(1))
    KEXPECT_EQ(0, is_signal_pending(proc_get(1), SIGAPOSTEST));

  // TODO(aoates): is there any scenario in which a process wouldn't be able to
  // send a signal to itself, and therefore proc_kill(-1, X) would return
  // -EPERM?
}

struct victim_args {
  int signum;
  struct ksigaction action;
  kthread_queue_t queue;
  bool interruptable;
  ksigset_t mask;
};

static void interrupted_handler(int signum) {
  // This never actually runs.
}

static void signal_interrupt_victim(void* arg) {
  struct victim_args* args = (struct victim_args*)arg;

  // TODO(aoates): use the appropriate syscall when available.
  proc_current_thread()->signal_mask = args->mask;

  int result = proc_sigaction(args->signum, &args->action, NULL);
  if (result) {
    klogfm(KL_TEST, WARNING, "sigaction() failed: %s\n",
           errorname(-result));
    proc_exit(-1);
  }

  result = 0;
  if (args->interruptable) {
    result = scheduler_wait_on_interruptable(&args->queue, -1);
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
    proc_force_signal_on_thread(proc_get(child),
                                get_proc_thread(proc_get(child)), args.signum);

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
    proc_force_signal_on_thread(proc_get(child),
                                get_proc_thread(proc_get(child)), args.signum);

    KEXPECT_EQ(1, kthread_queue_empty(&args.queue));
    scheduler_wake_all(&args.queue);

    int status;
    KEXPECT_EQ(child, proc_wait(&status));
    KEXPECT_EQ(1, status);
  }

  // TODO(aoates): tests for various sa_flags when they're implemented.
}

static void ksleep_interrupted_func(void* arg) {
  proc_exit(ksleep((intptr_t)arg));
}

static void ksleep_interrupted_test(void) {
  KTEST_BEGIN("ksleep(): interrupted by signal test");

  int child = proc_fork(&ksleep_interrupted_func, (void*)200);

  const apos_ms_t start_time = get_time_ms();
  ksleep(20);

  KEXPECT_EQ(0, proc_kill(child, SIGALRM));

  int exit_status = 0;
  KEXPECT_EQ(child, proc_wait(&exit_status));
  const apos_ms_t end_time = get_time_ms();

  KEXPECT_GE(end_time - start_time, 20);
  KEXPECT_LE(end_time - start_time, 60);
  KEXPECT_GE(exit_status, 160);
  KEXPECT_LE(exit_status, 180);
}

static void sigprocmask_test(void) {
  // (cheating)
  const ksigset_t orig_mask = kthread_current_thread()->signal_mask;

  KTEST_BEGIN("sigprocmask(): block signals");
  ksigset_t mask, mask2;
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

static void sigpending_test(void) {
  KTEST_BEGIN("sigpending() test -- unassigned signal");
  ksigemptyset(&proc_current_thread()->assigned_signals);

  ksigset_t orig_mask;
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &orig_mask));

  ksigset_t mask;
  ksigemptyset(&mask);
  ksigaddset(&mask, SIGUSR1);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, NULL));

  proc_force_signal(proc_current(), SIGUSR1);
  KEXPECT_EQ(1, ksigismember(&proc_current()->pending_signals, SIGUSR1));
  ksigset_t pending;
  KEXPECT_EQ(0, proc_sigpending(&pending));
  KEXPECT_EQ(1, ksigismember(&pending, SIGUSR1));
  ksigdelset(&pending, SIGUSR1);
  KEXPECT_EQ(1, ksigisemptyset(pending));

  KTEST_BEGIN("sigpending() test -- assigned and unblocked signal");
  ksigemptyset(&mask);
  ksigaddset(&mask, SIGUSR1);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &mask, NULL));
  proc_assign_pending_signals();

  KEXPECT_EQ(0, ksigismember(&proc_current()->pending_signals, SIGUSR1));
  pending = 123;
  KEXPECT_EQ(0, proc_sigpending(&pending));
  // Not blocked, so shouldn't be present.
  KEXPECT_EQ(1, ksigisemptyset(pending));

  KTEST_BEGIN("sigpending() test -- assigned and blocked signal");
  ksigemptyset(&mask);
  ksigaddset(&mask, SIGUSR1);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, NULL));
  proc_assign_pending_signals();

  KEXPECT_EQ(0, ksigismember(&proc_current()->pending_signals, SIGUSR1));
  pending = 123;
  KEXPECT_EQ(0, proc_sigpending(&pending));
  KEXPECT_EQ(1, ksigismember(&pending, SIGUSR1));
  ksigemptyset(&pending);
  KEXPECT_EQ(1, ksigisemptyset(pending));

  // Cleanup.
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &orig_mask, NULL));
  ksigdelset(&kthread_current_thread()->assigned_signals, SIGUSR1);
}

static ksigset_t make_empty_sigset(void) {
  ksigset_t s;
  ksigemptyset(&s);
  return s;
}

static ksigset_t make_sigset(int sig) {
  ksigset_t s;
  ksigemptyset(&s);
  ksigaddset(&s, sig);
  return s;
}

static ksigset_t make_sigset2(int sig1, int sig2) {
  ksigset_t s = make_sigset(sig1);
  ksigaddset(&s, sig2);
  return s;
}

static ksigset_t make_sigset3(int sig1, int sig2, int sig3) {
  ksigset_t s = make_sigset2(sig1, sig2);
  ksigaddset(&s, sig3);
  return s;
}

static void dispatchable_test(void) {
  KTEST_BEGIN("proc_dispatchable_signals(): basic test");
  KEXPECT_EQ(make_empty_sigset(), proc_dispatchable_signals());

  proc_force_signal(proc_current(), SIGUSR1);
  KEXPECT_EQ(make_sigset(SIGUSR1), proc_dispatchable_signals());

  proc_force_signal(proc_current(), SIGUSR2);
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());


  KTEST_BEGIN("proc_dispatchable_signals(): ignores masked signals");
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());

  ksigset_t mask = make_sigset(SIGUSR2);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &mask, NULL));
  KEXPECT_EQ(make_sigset(SIGUSR1), proc_dispatchable_signals());
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &mask, NULL));
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());


  KTEST_BEGIN("proc_dispatchable_signals(): ignores ignored signals");
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());

  struct ksigaction action;
  action.sa_handler = SIG_IGN;
  action.sa_flags = 0;
  ksigemptyset(&action.sa_mask);

  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &action, NULL));
  KEXPECT_EQ(make_sigset(SIGUSR2), proc_dispatchable_signals());

  action.sa_handler = SIG_DFL;
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &action, NULL));
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());


  KTEST_BEGIN("proc_dispatchable_signals(): ignores default-ignored signals");
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());
  proc_force_signal(proc_current(), SIGURG);

  action.sa_handler = SIG_DFL;
  KEXPECT_EQ(0, proc_sigaction(SIGURG, &action, NULL));
  KEXPECT_EQ(make_sigset2(SIGUSR1, SIGUSR2), proc_dispatchable_signals());

  action.sa_handler = sighandler;
  KEXPECT_EQ(0, proc_sigaction(SIGURG, &action, NULL));
  KEXPECT_EQ(make_sigset3(SIGUSR1, SIGUSR2, SIGURG),
             proc_dispatchable_signals());

  proc_suppress_signal(proc_current(), SIGUSR1);
  proc_suppress_signal(proc_current(), SIGUSR2);
  proc_suppress_signal(proc_current(), SIGURG);
}

typedef struct {
  int read_fd;
  int write_fd;
} sem_t;

static int sem_create(sem_t* sem) {
  int fds[2];
  int result = vfs_pipe(fds);
  if (result) return result;
  sem->read_fd = fds[0];
  sem->write_fd = fds[1];
  return 0;
}

static void sem_destroy(sem_t* sem) {
  vfs_close(sem->read_fd);
  vfs_close(sem->write_fd);
}

static int sem_wait(const sem_t* sem) {
  char buf;
  int result = vfs_read(sem->read_fd, &buf, 1);
  return (result < 0) ? result : 0;
}

static int sem_signal(const sem_t* sem) {
  int result = vfs_write(sem->write_fd, "x", 1);
  return (result < 0) ? result : 0;
}

static bool suspend_done = false;
static sem_t g_sem;
static void sigsuspend_test_child(void* arg) {
  const ksigset_t orig_mask = make_sigset(SIGHUP);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &orig_mask, NULL));

  struct ksigaction act;
  act.sa_handler = SIG_IGN;
  act.sa_mask = 0;
  act.sa_flags = 0;
  KEXPECT_EQ(0, proc_sigaction(SIGALRM, &act, NULL));

  KEXPECT_EQ(0, sem_signal(&g_sem));
  suspend_done = false;
  int result = proc_sigsuspend((const ksigset_t*)arg);
  KEXPECT_EQ(-EINTR, result);
  suspend_done = true;

  ksigset_t final_mask;
  KEXPECT_EQ(orig_mask, kthread_current_thread()->syscall_ctx.restore_mask);
  KEXPECT_NE(0,
             kthread_current_thread()->syscall_ctx.flags & SCCTX_RESTORE_MASK);
  KEXPECT_EQ(0, proc_sigprocmask(0, NULL, &final_mask));
  KEXPECT_EQ(*(const ksigset_t*)arg & ~make_sigset2(SIGKILL, SIGSTOP),
             final_mask);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &orig_mask, NULL));
}

static void sigsuspend_test(void) {
  KTEST_BEGIN("sigsuspend(): basic test");
  ksigset_t new_mask = make_sigset(SIGUSR2), old_mask;
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &new_mask, &old_mask));
  KEXPECT_EQ(0, sem_create(&g_sem));
  kpid_t child = proc_fork(&sigsuspend_test_child, &new_mask);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));
  KEXPECT_EQ(PROC_RUNNING, proc_get(child)->state);
  KEXPECT_EQ(new_mask, get_proc_thread(proc_get(child))->signal_mask);

  KEXPECT_EQ(0, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("sigsuspend(): sets and resets mask");
  ksigset_t mask2 = new_mask;
  ksigaddset(&mask2, SIGINT);
  child = proc_fork(&sigsuspend_test_child, &mask2);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));
  KEXPECT_EQ(PROC_RUNNING, proc_get(child)->state);
  KEXPECT_EQ(mask2, get_proc_thread(proc_get(child))->signal_mask);

  KEXPECT_EQ(0, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("sigsuspend(): ignores masked signals");
  mask2 = new_mask;
  ksigaddset(&mask2, SIGINT);
  child = proc_fork(&sigsuspend_test_child, &mask2);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));

  KEXPECT_EQ(0, proc_kill(child, SIGINT));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(false, suspend_done);
  KEXPECT_EQ(0, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("sigsuspend(): ignores default-ignored signals");
  const struct ksigaction kDefaultAction = {SIG_DFL, 0, 0};
  KEXPECT_EQ(0, proc_sigaction(SIGURG, &kDefaultAction, NULL));

  child = proc_fork(&sigsuspend_test_child, &mask2);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));

  KEXPECT_EQ(0, proc_kill(child, SIGURG));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(false, suspend_done);
  KEXPECT_EQ(0, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("sigsuspend(): ignores ignored signals");
  child = proc_fork(&sigsuspend_test_child, &mask2);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));

  KEXPECT_EQ(0, proc_kill(child, SIGALRM));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  KEXPECT_EQ(false, suspend_done);
  KEXPECT_EQ(0, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("sigsuspend(): cannot mask SIGKILL");
  mask2 = new_mask;
  ksigaddset(&mask2, SIGKILL);
  child = proc_fork(&sigsuspend_test_child, &mask2);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));

  KEXPECT_EQ(0, proc_kill(child, SIGKILL));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("sigsuspend(): cannot mask SIGSTOP");
  mask2 = new_mask;
  ksigaddset(&mask2, SIGSTOP);
  child = proc_fork(&sigsuspend_test_child, &mask2);
  KEXPECT_GE(child, 0);

  KEXPECT_EQ(0, sem_wait(&g_sem));

  KEXPECT_EQ(0, proc_kill(child, SIGSTOP));
  KEXPECT_EQ(child, proc_wait(NULL));


  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_mask, NULL));
  sem_destroy(&g_sem);
}

static void do_nothing(void* arg) {}

static void zombie_test(void) {
  KTEST_BEGIN("kill(): sending a signal to a zombie process");
  kpid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_GE(child, 0);
  while (proc_get(child)->state != PROC_ZOMBIE) {
    scheduler_yield();
  }

  KEXPECT_EQ(0, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(0, proc_kill(child, SIGTERM));
  KEXPECT_EQ(0, proc_force_signal(proc_get(child), SIGUSR2));

  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(1, WIFEXITED(status));
}

void signal_test(void) {
  KTEST_SUITE_BEGIN("signals");

  // Save the current signal handlers to restore at the end.
  ksigaction_t saved_handlers[APOS_SIGMAX + 1];
  for (int signum = APOS_SIGMIN; signum <= APOS_SIGMAX; ++signum) {
    KASSERT(proc_sigaction(signum, 0x0, &saved_handlers[signum]) == 0);
  }
  ksigset_t saved_pending_signals = proc_current()->pending_signals;
  ksigset_t saved_assigned_signals = proc_current_thread()->assigned_signals;
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
  sigpending_test();

  dispatchable_test();
  sigsuspend_test();
  zombie_test();

  // Restore all the signal handlers in case any of the tests didn't clean up.
  for (int signum = APOS_SIGMIN; signum <= APOS_SIGMAX; ++signum) {
    if (signum != SIGSTOP && signum != SIGKILL) {
      KASSERT(proc_sigaction(signum, &saved_handlers[signum], 0x0) == 0);
    }
  }
  proc_current()->pending_signals = saved_pending_signals;
  proc_current_thread()->assigned_signals = saved_assigned_signals;
}
