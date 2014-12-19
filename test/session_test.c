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

#include "common/kassert.h"
#include "dev/ld.h"
#include "dev/tty.h"
#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/tcgroup.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "vfs/vfs.h"

static void do_nothing(void* arg) {}
static void do_sleep(void* arg) {
  ksleep(10000);
}

static void do_setsid(void* arg) {
  KEXPECT_EQ(0, setpgid(0, 0));
  KEXPECT_NE(getpgid(0), proc_getsid(0));
  const pid_t session = proc_getsid(0);
  KEXPECT_EQ(-EPERM, proc_setsid());
  KEXPECT_EQ(session, proc_getsid(0));
}

static void do_setsid2(void* arg) {
  KEXPECT_EQ(0, proc_setsid());
  *(bool*)arg = true;
  ksleep(10);
}

static void do_setpgid(void* arg) {
  KEXPECT_EQ(0, setpgid(0, 0));
  *(bool*)arg = true;
  ksleep(10);
}

static void session_leader_pgid(void* arg) {
  KEXPECT_EQ(0, proc_setsid());

  KEXPECT_EQ(-EPERM, setpgid(0, 0));
  KEXPECT_EQ(-EPERM, setpgid(proc_current()->id, proc_current()->id));
  KEXPECT_EQ(-EPERM, setpgid(proc_current()->id, proc_current()->parent->id));
  KEXPECT_EQ(proc_current()->id, getpgid(0));
  *(bool*)arg = true;
  ksleep(10);
}

static void child_different_session_test(void* arg) {
  // We run this in a different session to ensure that the parent process (this
  // process) isn't a session leader (so we can setsid() after forking the
  // child).
  pid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(proc_getsid(0), proc_getsid(child));
  KEXPECT_EQ(0, proc_setsid());
  KEXPECT_NE(proc_getsid(0), proc_getsid(child));
  KEXPECT_EQ(-EPERM, setpgid(child, child));
  KEXPECT_EQ(-EPERM, setpgid(child, proc_current()->id));
  KEXPECT_EQ(-EPERM, setpgid(child, proc_current()->parent->id));
  KEXPECT_EQ(child, proc_wait(NULL));
}

static void child_set_pgid(void* arg) {
  pid_t target_pgroup = (pid_t)arg;
  KEXPECT_EQ(-EPERM, setpgid(0, target_pgroup));
}

static void set_pgid_across_sessions_test(void* arg) {
  const sid_t orig_session = proc_getsid(0);
  const pid_t orig_pgroup = getpgid(0);

  KEXPECT_EQ(0, proc_setsid());
  pid_t child = proc_fork(&child_set_pgid, (void*)orig_pgroup);
  KEXPECT_EQ(-EPERM, setpgid(child, orig_pgroup));
  KEXPECT_EQ(child, proc_wait(NULL));
  KEXPECT_EQ(orig_session, proc_group_get(orig_pgroup)->session);
}

static void change_user(void* arg) {
  KEXPECT_EQ(0, setuid(4));
  *(bool*)arg = true;
  ksleep(10);
}

static void change_user_test(void* arg) {
  bool wait = false;
  pid_t child = proc_fork(&change_user, &wait);
  for (int i = 0; i < 10 && !wait; ++i) scheduler_yield();

  KEXPECT_EQ(0, setuid(3));
  KEXPECT_EQ(-EPERM, proc_kill(child, SIGSTOP));
  KEXPECT_EQ(-EPERM, proc_kill(child, SIGUSR1));
  KEXPECT_EQ(-EPERM, proc_kill(child, SIGURG));
  KEXPECT_EQ(-EPERM, proc_kill(child, SIGSTOP));
  KEXPECT_EQ(0, proc_kill(child, SIGCONT));

  KTEST_BEGIN("cannot send SIGCONT across sessions");
  KEXPECT_EQ(0, proc_setsid());
  KEXPECT_EQ(-EPERM, proc_kill(child, SIGCONT));

  KEXPECT_EQ(child, proc_wait(NULL));
}

static void do_session_test(void* arg) {
  KTEST_BEGIN("getsid() basic test");
  KEXPECT_GE(proc_getsid(proc_current()->id), 0);
  KEXPECT_GE(proc_getsid(0), 0);
  KEXPECT_GE(proc_getsid(0), proc_getsid(proc_current()->id));

  KTEST_BEGIN("getsid() invalid pid");
  KEXPECT_EQ(-ESRCH, proc_getsid(-1));
  KEXPECT_EQ(-ESRCH, proc_getsid(-10));
  KEXPECT_EQ(-ESRCH, proc_getsid(PROC_MAX_PROCS));
  KEXPECT_EQ(-ESRCH, proc_getsid(PROC_MAX_PROCS + 1));

  pid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(proc_getsid(0), proc_getsid(child));
  KEXPECT_EQ(child, proc_wait(NULL));
  KEXPECT_EQ(-ESRCH, proc_getsid(child));


  KTEST_BEGIN("setsid() basic");
  KEXPECT_NE(proc_current()->id, proc_current()->pgroup);
  KEXPECT_EQ(0, proc_setsid());
  KEXPECT_EQ(proc_current()->id, proc_current()->pgroup);
  KEXPECT_EQ(proc_current()->id, getpgid(0));
  KEXPECT_EQ(proc_current()->id,
             proc_group_get(proc_current()->pgroup)->session);
  KEXPECT_EQ(proc_current()->id, proc_getsid(0));
  KEXPECT_EQ(proc_current()->id, proc_getsid(proc_current()->id));

  KEXPECT_EQ(PROC_SESSION_NO_CTTY, proc_session_get(proc_getsid(0))->ctty);

  KTEST_BEGIN("setsid() fails if already process group leader");
  KEXPECT_EQ(-EPERM, proc_setsid());
  KEXPECT_EQ(proc_current()->id, getpgid(0));
  KEXPECT_EQ(proc_current()->id, proc_getsid(0));
  child = proc_fork(&do_setsid, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("getsid() on process in a different group in the same session");
  bool wait = false;
  child = proc_fork(&do_setpgid, &wait);
  KEXPECT_EQ(proc_getsid(0), proc_getsid(child));
  KEXPECT_EQ(proc_getsid(proc_current()->id), proc_getsid(child));
  for (int i = 0; i < 10 && !wait; ++i) scheduler_yield();

  KEXPECT_EQ(child, getpgid(child));
  KEXPECT_NE(getpgid(0), getpgid(child));
  KEXPECT_EQ(proc_getsid(0), proc_getsid(child));

  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("getsid() and getpgid() fail on process in different session");
  wait = false;
  child = proc_fork(&do_setsid2, &wait);
  KEXPECT_EQ(proc_getsid(0), proc_getsid(child));
  for (int i = 0; i < 10 && !wait; ++i) scheduler_yield();
  KEXPECT_EQ(true, wait);
  KEXPECT_EQ(-EPERM, proc_getsid(child));
  KEXPECT_EQ(-EPERM, getpgid(child));
  KEXPECT_EQ(0, proc_kill(child, SIGKILL));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("setpgid(): cannot change the process group of a session leader");
  wait = false;
  child = proc_fork(&session_leader_pgid, &wait);
  for (int i = 0; i < 10 && !wait; ++i) scheduler_yield();
  KEXPECT_EQ(-EPERM, setpgid(child, child));
  KEXPECT_EQ(-EPERM, setpgid(child, proc_current()->id));
  KEXPECT_EQ(child, proc_get(child)->pgroup);
  KEXPECT_EQ(0, proc_kill(child, SIGKILL));
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("setpgid(): cannot change process group of a child in a "
              "different session (but not a session leader)");
  child = proc_fork(&child_different_session_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("setpgid(): cannot change to process group in another session");
  child = proc_fork(&set_pgid_across_sessions_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("kill() can send SIGCONT across users within a session");
  child = proc_fork(&change_user_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));


  KTEST_BEGIN("setpgid(): on another process updates session");
  child = proc_fork(&do_nothing, NULL);
  KASSERT(list_empty(&proc_group_get(child)->procs));
  proc_group_get(child)->session = PROC_MAX_PROCS - 1;

  KEXPECT_EQ(0, setpgid(child, 0));
  KEXPECT_EQ(child, getpgid(child));
  KEXPECT_EQ(proc_current()->id, proc_group_get(child)->session);

  KEXPECT_EQ(child, proc_wait(NULL));

  // TODO(aoates): test reusing an process group ID, and that the session is
  // updated nonetheless.
  // TODO(aoates): test if there's an existing ctty, that its reset when a new
  // session is created.
}

// Helper for the below.  Open the given TTY and return the fd.
static int open_tty(apos_dev_t test_tty, int flags) {
  char name[20];
  ksprintf(name, "/dev/tty%d", minor(test_tty));
  int fd = vfs_open(name, VFS_O_RDONLY | flags);
  KEXPECT_GE(fd, 0);
  return fd;
}

// Helper for the below.  Create a new session and open the given TTY.
static int setsid_and_open_tty(apos_dev_t test_tty) {
  KEXPECT_EQ(0, proc_setsid());
  KEXPECT_EQ(PROC_SESSION_NO_CTTY, proc_session_get(proc_getsid(0))->ctty);

  return open_tty(test_tty, 0);
}

static void do_open_ctty(void* arg) {
  KTEST_BEGIN("vfs_open() sets ctty");
  const apos_dev_t test_tty = (apos_dev_t)arg;
  KEXPECT_EQ(-1, tty_get(test_tty)->session);
  setsid_and_open_tty(test_tty);

  KEXPECT_EQ(minor(test_tty), proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(proc_getsid(0), tty_get(test_tty)->session);
}

static void open_tty_shouldnt_set_ctty(void* arg) {
  const apos_dev_t test_tty = (apos_dev_t)arg;
  const sid_t orig_tty_session = tty_get(test_tty)->session;
  setsid_and_open_tty(test_tty);

  KEXPECT_EQ(PROC_SESSION_NO_CTTY, proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(orig_tty_session, tty_get(test_tty)->session);
}

static void do_open_another_ctty_test(void* arg) {
  KTEST_BEGIN("vfs_open() doesn't poach another session's ctty");
  const apos_dev_t test_tty = (apos_dev_t)arg;
  KEXPECT_EQ(-1, tty_get(test_tty)->session);
  setsid_and_open_tty(test_tty);

  KEXPECT_EQ(minor(test_tty), proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(proc_getsid(0), tty_get(test_tty)->session);

  pid_t child = proc_fork(&open_tty_shouldnt_set_ctty, arg);
  KEXPECT_EQ(child, proc_wait(NULL));

  KEXPECT_EQ(minor(test_tty), proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(proc_getsid(0), tty_get(test_tty)->session);
}

static void open_second_tty(void* arg) {
  KTEST_BEGIN("vfs_open() doesn't change ctty if the session already has one");
  ld_t* const test_ld2 = ld_create(100);
  const apos_dev_t test_tty2 = tty_create(test_ld2);

  const apos_dev_t test_tty = (apos_dev_t)arg;
  setsid_and_open_tty(test_tty);

  open_tty(test_tty2, 0);

  KEXPECT_EQ(minor(test_tty), proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(proc_getsid(0), tty_get(test_tty)->session);
  KEXPECT_EQ(-1, tty_get(test_tty2)->session);

  tty_destroy(test_tty2);
  ld_destroy(test_ld2);
}

static void open_tty_subproc(void* arg) {
  open_tty((apos_dev_t)arg, 0);
}

static void non_leader_exit_doesnt_release_ctty(void* arg) {
  KTEST_BEGIN("exit() from a non-session-leader doesn't release the CTTY");
  const apos_dev_t test_tty = (apos_dev_t)arg;
  setsid_and_open_tty(test_tty);

  pid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&open_tty_subproc, arg);
  KEXPECT_EQ(child, proc_wait(NULL));

  KEXPECT_EQ(minor(test_tty), proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(proc_getsid(0), tty_get(test_tty)->session);
}

static void non_leader_open_doesnt_set_ctty(void* arg) {
  KTEST_BEGIN("open(TTY) from a non-session-leader doesn't set the CTTY");
  KEXPECT_EQ(0, proc_setsid());
  pid_t child = proc_fork(&open_tty_subproc, arg);
  KEXPECT_EQ(child, proc_wait(NULL));

  KEXPECT_EQ(PROC_SESSION_NO_CTTY, proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(-1, tty_get((apos_dev_t)arg)->session);
}

static void no_ctty_flag(void* arg) {
  KTEST_BEGIN("open(O_NOCTTY) doesn't set the CTTY");
  KEXPECT_EQ(0, proc_setsid());

  KEXPECT_EQ(PROC_SESSION_NO_CTTY, proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(-1, tty_get((apos_dev_t)arg)->session);

  open_tty((apos_dev_t)arg, VFS_O_NOCTTY);

  KEXPECT_EQ(PROC_SESSION_NO_CTTY, proc_session_get(proc_getsid(0))->ctty);
  KEXPECT_EQ(-1, tty_get((apos_dev_t)arg)->session);
}

static void ctty_test(void* arg) {
  ld_t* const test_ld = ld_create(100);
  const apos_dev_t test_tty = tty_create(test_ld);

  pid_t child = proc_fork(&do_open_ctty, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));
  KEXPECT_EQ(-1, tty_get(test_tty)->session);

  child = proc_fork(&do_open_another_ctty_test, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&open_second_tty, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&non_leader_exit_doesnt_release_ctty, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&non_leader_open_doesnt_set_ctty, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&no_ctty_flag, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(test_tty);
  ld_destroy(test_ld);
}

static int sig_is_pending(process_t* proc, int sig) {
  sigset_t pending = proc_pending_signals(proc);
  return ksigismember(&pending, sig);
}

static void empty_sig_handler(int sig) {}

static void tcsetpgrp_test_inner(void* arg) {
  sigset_t sigset_mask_ttou, old_sigset;
  ksigemptyset(&sigset_mask_ttou);
  ksigaddset(&sigset_mask_ttou, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &sigset_mask_ttou, &old_sigset));

  ld_t* const test_ldB = ld_create(100);
  const apos_dev_t test_tty = *(apos_dev_t*)arg;
  const apos_dev_t test_ttyB = tty_create(test_ldB);
  char tty_name[20], tty_nameB[20];
  ksprintf(tty_name, "/dev/tty%u", minor(test_tty));
  ksprintf(tty_nameB, "/dev/tty%u", minor(test_ttyB));

  KTEST_BEGIN("tcsetpgrp(): no controlling terminal");
  KEXPECT_EQ(0, proc_setsid());
  int fd = vfs_open(tty_name, VFS_O_RDONLY | VFS_O_NOCTTY);
  KEXPECT_EQ(-ENOTTY, proc_tcsetpgrp(fd, proc_current()->pgroup));

  KTEST_BEGIN("tcgetpgrp(): no controlling terminal");
  KEXPECT_EQ(-ENOTTY, proc_tcgetpgrp(fd));
  vfs_close(fd);


  KTEST_BEGIN("tcgetpgrp(): no foregroup process group");
  fd = vfs_open(tty_name, VFS_O_RDONLY);
  KEXPECT_EQ(PROC_NO_FGGRP, proc_tcgetpgrp(fd));

  KTEST_BEGIN(
      "tcgetpgrp()/tcsetpgrp()/tcgetsid(): fd is not a controlling terminal");
  int fd2 = vfs_open(tty_nameB, VFS_O_RDONLY | VFS_O_NOCTTY);
  KEXPECT_EQ(-ENOTTY, proc_tcgetpgrp(fd2));
  KEXPECT_EQ(-ENOTTY, proc_tcsetpgrp(fd2, getpgid(0)));
  KEXPECT_EQ(-ENOTTY, proc_tcgetsid(fd2));
  vfs_close(fd2);
  fd2 = vfs_open("ctty_test_file", VFS_O_CREAT | VFS_O_RDONLY, VFS_S_IRWXU);
  KEXPECT_EQ(-ENOTTY, proc_tcgetpgrp(fd2));
  KEXPECT_EQ(-ENOTTY, proc_tcsetpgrp(fd2, getpgid(0)));
  KEXPECT_EQ(-ENOTTY, proc_tcgetsid(fd2));
  vfs_close(fd2);
  KEXPECT_EQ(0, vfs_unlink("ctty_test_file"));


  KTEST_BEGIN("tcsetpgrp(): bad process group ID");
  KEXPECT_EQ(-EINVAL, proc_tcsetpgrp(fd, -1));
  KEXPECT_EQ(-EINVAL, proc_tcsetpgrp(fd, PROC_MAX_PROCS));
  KEXPECT_EQ(-EINVAL, proc_tcsetpgrp(fd, PROC_MAX_PROCS + 1));
  KEXPECT_EQ(-EINVAL, proc_tcsetpgrp(fd, PROC_MAX_PROCS + 5));


  KTEST_BEGIN("tcsetpgrp(): set initial group");
  KEXPECT_EQ(0, proc_tcsetpgrp(fd, getpgid(0)));
  KEXPECT_EQ(getpgid(0), proc_tcgetpgrp(fd));
  KEXPECT_EQ(proc_getsid(0), proc_tcgetsid(fd));


  // Restore the signal mask.
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_sigset, NULL));


  KTEST_BEGIN("tcsetpgrp(): set fg group from fg group to same group");
  const pid_t childA = proc_fork(&do_sleep, NULL);
  const pid_t childB = proc_fork(&do_sleep, NULL);
  const pid_t childC = proc_fork(&do_sleep, NULL);
  KEXPECT_EQ(0, proc_tcsetpgrp(fd, getpgid(0)));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTTOU));
  KEXPECT_EQ(getpgid(0), proc_tcgetpgrp(fd));


  KTEST_BEGIN("tcsetpgrp(): set fg group from fg group to another group");
  // Put the child in another pgroup and make it the foreground.
  KEXPECT_EQ(0, setpgid(childA, childA));
  KEXPECT_EQ(0, proc_tcsetpgrp(fd, childA));
  KEXPECT_EQ(childA, proc_tcgetpgrp(fd));
  KEXPECT_EQ(proc_getsid(0), proc_tcgetsid(fd));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGTTOU));


  KTEST_BEGIN("tcsetpgrp(): set fg group from bg group with SIGTTOU blocked");
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &sigset_mask_ttou, NULL));
  KEXPECT_EQ(0, setpgid(childB, childB));
  KEXPECT_EQ(0, proc_tcsetpgrp(fd, childB));
  KEXPECT_EQ(childB, proc_tcgetpgrp(fd));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGTTOU));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &sigset_mask_ttou, NULL));


  KTEST_BEGIN("tcsetpgrp(): set fg group from bg group with SIGTTOU ignored");
  struct sigaction sigact = {SIG_IGN, 0, 0}, oldact;
  KEXPECT_EQ(0, proc_sigaction(SIGTTOU, &sigact, &oldact));

  KEXPECT_EQ(0, proc_tcsetpgrp(fd, childA));
  KEXPECT_EQ(childA, proc_tcgetpgrp(fd));
  KEXPECT_EQ(proc_getsid(0), proc_tcgetsid(fd));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childC), SIGTTOU));
  KEXPECT_EQ(0, proc_sigaction(SIGTTOU, &oldact, NULL));


  KTEST_BEGIN("tcsetpgrp(): set fg group from bg group with SIGTTOU default");
  KEXPECT_EQ(-EINTR, proc_tcsetpgrp(fd, childB));
  KEXPECT_EQ(childA, proc_tcgetpgrp(fd));  // Shouldn't have gone through.
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGTTOU));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childC), SIGTTOU));
  proc_suppress_signal(proc_current(), SIGTTOU);
  proc_suppress_signal(proc_get(childC), SIGTTOU);


  KTEST_BEGIN("tcsetpgrp(): set fg group from bg group with SIGTTOU handled");
  sigact.sa_handler = &empty_sig_handler;
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(-EINTR, proc_tcsetpgrp(fd, childB));
  KEXPECT_EQ(childA, proc_tcgetpgrp(fd));  // Shouldn't have gone through.
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childA), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_get(childB), SIGTTOU));
  KEXPECT_EQ(1, sig_is_pending(proc_get(childC), SIGTTOU));
  proc_suppress_signal(proc_current(), SIGTTOU);
  proc_suppress_signal(proc_get(childC), SIGTTOU);


  KTEST_BEGIN("tcsetpgrp(): set fg group to non-existant pgroup");
  const pid_t childD = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(childD, proc_wait(NULL));

  KEXPECT_EQ(-EPERM, proc_tcsetpgrp(fd, childD));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));


  KTEST_BEGIN("tcsetpgrp(): set fg group to pgroup in another session");
  bool wait = false;
  const pid_t childE = proc_fork(&do_setsid2, &wait);
  for (int i = 0; i < 10 && !wait; ++i) scheduler_yield();

  KEXPECT_EQ(-EPERM, proc_tcsetpgrp(fd, childE));
  KEXPECT_EQ(childE, proc_wait(NULL));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));


  vfs_close(fd);
  KEXPECT_EQ(0, proc_force_signal(proc_get(childA), SIGKILL));
  KEXPECT_EQ(childA, proc_wait(NULL));
  KEXPECT_EQ(0, proc_force_signal(proc_get(childB), SIGKILL));
  KEXPECT_EQ(childB, proc_wait(NULL));
  KEXPECT_EQ(0, proc_force_signal(proc_get(childC), SIGKILL));
  KEXPECT_EQ(childC, proc_wait(NULL));


  KTEST_BEGIN("tcsetpgrp(): bad file descriptor");
  fd = vfs_open(tty_name, VFS_O_RDONLY | VFS_O_NOCTTY);
  vfs_close(fd);
  KEXPECT_EQ(-EBADF, proc_tcsetpgrp(-5, proc_current()->pgroup));
  KEXPECT_EQ(-EBADF, proc_tcsetpgrp(PROC_MAX_FDS, proc_current()->pgroup));
  KEXPECT_EQ(-EBADF, proc_tcsetpgrp(PROC_MAX_FDS + 1, proc_current()->pgroup));
  KEXPECT_EQ(-EBADF, proc_tcsetpgrp(fd, proc_current()->pgroup));

  KTEST_BEGIN("tcgetpgrp(): bad file descriptor");
  KEXPECT_EQ(-EBADF, proc_tcgetpgrp(-5));
  KEXPECT_EQ(-EBADF, proc_tcgetpgrp(PROC_MAX_FDS));
  KEXPECT_EQ(-EBADF, proc_tcgetpgrp(PROC_MAX_FDS + 1));
  KEXPECT_EQ(-EBADF, proc_tcgetpgrp(fd));

  KTEST_BEGIN("tcgetsid(): bad file descriptor");
  KEXPECT_EQ(-EBADF, proc_tcgetsid(-5));
  KEXPECT_EQ(-EBADF, proc_tcgetsid(PROC_MAX_FDS));
  KEXPECT_EQ(-EBADF, proc_tcgetsid(PROC_MAX_FDS + 1));
  KEXPECT_EQ(-EBADF, proc_tcgetsid(fd));


  // TODO(aoates): test orphaned pgroup with SIGTTOU
  // TODO(aoates): for both get and set: valid fd that's not a terminal,
  //  valid fd that's another session's ctty

  tty_destroy(test_ttyB);
  ld_destroy(test_ldB);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old_sigset, NULL));
}

static void tcsetpgrp_test(void* arg) {
  ld_t* const test_ld = ld_create(100);
  apos_dev_t test_tty = tty_create(test_ld);

  const pid_t child = proc_fork(&tcsetpgrp_test_inner, &test_tty);
  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(0, status);

  tty_destroy(test_tty);
  ld_destroy(test_ld);
}

typedef struct {
  bool set_ctty;
  bool make_fg;
  struct child {
    sigset_t signals;
    bool ran;
  } child[3];
  apos_dev_t tty;
} controlling_exit_args;

static void controlling_process_exit_subproc(void* arg) {
  struct child* x = (struct child*)arg;
  x->signals = proc_pending_signals(proc_current());
  x->ran = true;
}

static void controlling_process_exit_helper(void* arg) {
  controlling_exit_args* args = (controlling_exit_args*)arg;
  KEXPECT_GE(proc_setsid(), 0);

  int tty_fd = -1;
  if (args->set_ctty) {
    char tty_name[20];
    ksprintf(tty_name, "/dev/tty%d", minor(args->tty));
    tty_fd = vfs_open(tty_name, VFS_O_RDONLY);
    KEXPECT_GE(tty_fd, 0);
  }

  pid_t child[3];
  for (int i = 0; i < 3; ++i) {
    args->child[i].ran = false;
    args->child[i].signals = 0;
    child[i] =
        proc_fork(&controlling_process_exit_subproc, &args->child[i]);
  }

  KEXPECT_EQ(0, setpgid(child[0], child[0]));
  KEXPECT_EQ(0, setpgid(child[1], child[0]));
  KEXPECT_EQ(0, setpgid(child[2], child[2]));

  if (args->make_fg) {
    sigset_t set = 0;
    ksigaddset(&set, SIGTTOU);
    proc_sigprocmask(SIG_BLOCK, &set, NULL);
    KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, child[0]));
  }
}

static void controlling_exit_run_helper(controlling_exit_args* args) {
  const pid_t child = proc_fork(&controlling_process_exit_helper, args);
  int status;
  KEXPECT_EQ(child, proc_wait(&status));
  KEXPECT_EQ(0, status);

  for (int i = 0; i < 10; ++i) {
    if (args->child[0].ran && args->child[1].ran && args->child[2].ran) break;
    scheduler_yield();
  }
  KEXPECT_EQ(true, args->child[0].ran);
  KEXPECT_EQ(true, args->child[1].ran);
  KEXPECT_EQ(true, args->child[2].ran);
}

static void controlling_process_exit_test(void* arg) {
  const sigset_t kEmptySet = 0;
  sigset_t kSigHupSet;
  ksigemptyset(&kSigHupSet);
  ksigaddset(&kSigHupSet, SIGHUP);

  ld_t* const test_ld = ld_create(1);
  apos_dev_t test_tty = tty_create(test_ld);

  KTEST_BEGIN("SIGHUP to fg group when controlling proc exits (normal)");
  controlling_exit_args args;
  args.set_ctty = args.make_fg = true;
  args.tty = test_tty;
  controlling_exit_run_helper(&args);

  KEXPECT_EQ(kSigHupSet, args.child[0].signals);
  KEXPECT_EQ(kSigHupSet, args.child[1].signals);
  KEXPECT_EQ(kEmptySet, args.child[2].signals);


  KTEST_BEGIN("SIGHUP to fg group when controlling proc exits (no fg group)");
  args.set_ctty = true;
  args.make_fg = false;
  controlling_exit_run_helper(&args);

  KEXPECT_EQ(kEmptySet, args.child[0].signals);
  KEXPECT_EQ(kEmptySet, args.child[1].signals);
  KEXPECT_EQ(kEmptySet, args.child[2].signals);


  KTEST_BEGIN("SIGHUP to fg group when controlling proc exits (no CTTY)");
  args.set_ctty = false;
  args.make_fg = false;
  controlling_exit_run_helper(&args);

  KEXPECT_EQ(kEmptySet, args.child[0].signals);
  KEXPECT_EQ(kEmptySet, args.child[1].signals);
  KEXPECT_EQ(kEmptySet, args.child[2].signals);

  tty_destroy(test_tty);
  ld_destroy(test_ld);
}

static void read_from_bg_test_inner(void* arg) {
  const apos_dev_t test_tty = (apos_dev_t)arg;
  sigset_t kSigTtinSet;
  ksigemptyset(&kSigTtinSet);
  ksigaddset(&kSigTtinSet, SIGTTIN);

  KTEST_BEGIN("read() on CTTY from bg process (no signals blocked)");
  KEXPECT_EQ(0, proc_setsid());

  sigset_t ttou_mask;
  ksigemptyset(&ttou_mask);
  ksigaddset(&ttou_mask, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &ttou_mask, NULL));

  char tty_name[20];
  char buf;
  ksprintf(tty_name, "/dev/tty%d", minor(test_tty));
  int tty_fd = vfs_open(tty_name, VFS_O_RDONLY);
  KEXPECT_GE(tty_fd, 0);

  pid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(child, child));
  KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, child));

  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));
  KEXPECT_EQ(-EINTR, vfs_read(tty_fd, &buf, 1));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTIN));
  proc_suppress_signal(proc_current(), SIGTTIN);


  KTEST_BEGIN("read() on CTTY from bg process (handler set for SIGTTIN)");
  struct sigaction act = {&empty_sig_handler, 0, 0};
  KEXPECT_EQ(0, proc_sigaction(SIGTTIN, &act, NULL));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));
  KEXPECT_EQ(-EINTR, vfs_read(tty_fd, &buf, 1));
  KEXPECT_EQ(1, sig_is_pending(proc_current(), SIGTTIN));
  proc_suppress_signal(proc_current(), SIGTTIN);


  KTEST_BEGIN("read() on CTTY from bg process (SIGTTIN masked)");
  act.sa_handler = SIG_DFL;
  KEXPECT_EQ(0, proc_sigaction(SIGTTIN, &act, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &kSigTtinSet, NULL));

  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));
  KEXPECT_EQ(-EIO, vfs_read(tty_fd, &buf, 1));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));


  KTEST_BEGIN("read() on CTTY from bg process (SIGTTIN ignored)");
  act.sa_handler = SIG_IGN;
  KEXPECT_EQ(0, proc_sigaction(SIGTTIN, &act, NULL));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &kSigTtinSet, NULL));

  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));
  KEXPECT_EQ(-EIO, vfs_read(tty_fd, &buf, 1));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));


  KEXPECT_EQ(child, proc_wait(NULL));
  vfs_close(tty_fd);
}

static void read_from_bg_test(void* arg) {
  ld_t* const test_ld = ld_create(1);
  apos_dev_t test_tty = tty_create(test_ld);
  ld_set_tty(test_ld, test_tty);

  pid_t child = proc_fork(&read_from_bg_test_inner, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(test_tty);
  ld_destroy(test_ld);
}

static void write_from_bg_test_inner(void* arg) {
  const apos_dev_t test_tty = (apos_dev_t)arg;
  sigset_t kSigTtinSet;
  ksigemptyset(&kSigTtinSet);
  ksigaddset(&kSigTtinSet, SIGTTIN);

  KTEST_BEGIN("write() on CTTY from bg process (no signals blocked)");
  KEXPECT_EQ(0, proc_setsid());

  sigset_t ttou_mask;
  ksigemptyset(&ttou_mask);
  ksigaddset(&ttou_mask, SIGTTOU);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &ttou_mask, NULL));

  char tty_name[20];
  char buf;
  ksprintf(tty_name, "/dev/tty%d", minor(test_tty));
  int tty_fd = vfs_open(tty_name, VFS_O_WRONLY);
  KEXPECT_GE(tty_fd, 0);

  pid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(0, setpgid(child, child));
  KEXPECT_EQ(0, proc_tcsetpgrp(tty_fd, child));
  KEXPECT_EQ(0, proc_sigprocmask(SIG_UNBLOCK, &ttou_mask, NULL));

  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(1, vfs_write(tty_fd, &buf, 1));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTOU));
  KEXPECT_EQ(0, sig_is_pending(proc_current(), SIGTTIN));

  KEXPECT_EQ(child, proc_wait(NULL));
  vfs_close(tty_fd);
}

static void null_sink(void* arg, char c) {}

static void write_from_bg_test(void* arg) {
  ld_t* const test_ld = ld_create(1);
  apos_dev_t test_tty = tty_create(test_ld);
  ld_set_tty(test_ld, test_tty);
  ld_set_sink(test_ld, null_sink, NULL);

  pid_t child = proc_fork(&write_from_bg_test_inner, (void*)test_tty);
  KEXPECT_EQ(child, proc_wait(NULL));

  tty_destroy(test_tty);
  ld_destroy(test_ld);
}

void session_test(void) {
  KTEST_SUITE_BEGIN("process session tests");

  pid_t child = proc_fork(&do_session_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&ctty_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&tcsetpgrp_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&controlling_process_exit_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&read_from_bg_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&write_from_bg_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}
