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

#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/wait.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"

static void do_nothing(void* arg) {}

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

  // TODO(aoates): verify no controlling terminal.

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


  KTEST_BEGIN("getsid() fails on process in different session");
  wait = false;
  child = proc_fork(&do_setsid2, &wait);
  KEXPECT_EQ(proc_getsid(0), proc_getsid(child));
  for (int i = 0; i < 10 && !wait; ++i) scheduler_yield();
  KEXPECT_EQ(true, wait);
  KEXPECT_EQ(-EPERM, proc_getsid(child));
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

  // TODO(aoates): test adding a process to a process group in a different
  // session (should fail).
  // TODO(aoates): test reusing an process group ID, and that the session is
  // updated nonetheless.
  // TODO(aoates): setpgid on another process, creating a new pgroup (check
  // session)
}

void session_test(void) {
  KTEST_SUITE_BEGIN("process session tests");

  pid_t child = proc_fork(&do_session_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}
