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

// Tests for process groups.
#include <stdint.h>

#include "common/errno.h"
#include "common/kassert.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/process.h"
#include "proc/sleep.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"

static void basic_getgpid_test(void) {
  KTEST_BEGIN("getpgid() basic test");
  KEXPECT_GE(getpgid(proc_current()->id), 0);

  KTEST_BEGIN("getpgid() getpgid(0) gets current process's group");
  KEXPECT_EQ(getpgid(proc_current()->id), getpgid(0));

  KTEST_BEGIN("getpgid() invalid pid");
  KEXPECT_EQ(-EINVAL, getpgid(-1));
  KEXPECT_EQ(-EINVAL, getpgid(PROC_MAX_PROCS + 1));

  KTEST_BEGIN("getpgid() no process with pid");
  // TODO(aoates): find a better way of getting unused pid
  KEXPECT_EQ(-ESRCH, getpgid(100));
}

// Fork and run the given the given function in the child, and wait for it to
// exit.
static void fork_and_run(proc_func_t f, int arg) {
  int child_pid = proc_fork(f, (void*)arg);
  KEXPECT_EQ(child_pid, proc_wait(0x0));
}

static void loop_until_done(void* arg) {
  int* done = (int*)arg;
  while (!*done) {
    ksleep(10);
  }
}

static int group_contains(pid_t pgid, pid_t pid) {
  for (list_link_t* link = proc_group_get(pgid)->procs.head;
       link != 0x0;
       link = link->next) {
    process_t* proc = container_of(link, process_t, pgroup_link);
    if (proc->id == pid) return 1;
  }
  return 0;
}

static void basic_setgpid_test(void* arg) {
  const pid_t group = (pid_t)arg;

  // To ensure it's not looked at or carried to children.
  proc_current()->execed = true;

  KTEST_BEGIN("setgpid() create new group");
  KEXPECT_NE(proc_current()->id, getpgid(0));
  KEXPECT_EQ(getpgid(proc_current()->id), getpgid(0));

  KEXPECT_EQ(0, setpgid(proc_current()->id, proc_current()->id));
  KEXPECT_EQ(proc_current()->id, getpgid(0));
  KEXPECT_EQ(getpgid(proc_current()->id), getpgid(0));

  KEXPECT_EQ(1, group_contains(proc_current()->id, proc_current()->id));

  KTEST_BEGIN("setgpid() join existing group");
  KEXPECT_EQ(0, setpgid(proc_current()->id, group));
  KEXPECT_EQ(group, getpgid(0));
  KEXPECT_EQ(getpgid(proc_current()->id), getpgid(0));

  KEXPECT_EQ(1, group_contains(group, proc_current()->id));
  KEXPECT_EQ(0, group_contains(proc_current()->id, proc_current()->id));

  // For this test, we set it back to the current process group.
  KTEST_BEGIN("setgpid() pgid == 0 means use given pid as process group");
  // TODO(aoates): test pgid == 0 when setting another process's group as well.
  KEXPECT_EQ(0, setpgid(proc_current()->id, 0));
  KEXPECT_EQ(proc_current()->id, getpgid(0));

  KEXPECT_EQ(0, group_contains(group, proc_current()->id));
  KEXPECT_EQ(1, group_contains(proc_current()->id, proc_current()->id));

  // ...then back to the other group for this test.
  KTEST_BEGIN("setgpid() pid == 0 means set current process's group");
  KEXPECT_EQ(0, setpgid(0, group));
  KEXPECT_EQ(group, getpgid(0));

  KEXPECT_EQ(1, group_contains(group, proc_current()->id));
  KEXPECT_EQ(0, group_contains(proc_current()->id, proc_current()->id));

  // ...and finally back to itself for this test.
  KTEST_BEGIN("setgpid() pid == 0 and pgid == 0 means create new group");
  KEXPECT_EQ(0, setpgid(0, 0));
  KEXPECT_EQ(proc_current()->id, getpgid(0));

  KEXPECT_EQ(0, group_contains(group, proc_current()->id));
  KEXPECT_EQ(1, group_contains(proc_current()->id, proc_current()->id));
}

static void invalid_params_setgpid_test(void* arg) {
  const pid_t group = (pid_t)arg;
  const pid_t orig_group = getpgid(0);

  KTEST_BEGIN("setgpid() invalid pgid");
  KEXPECT_EQ(-EINVAL, setpgid(0, -5));
  KEXPECT_EQ(-EINVAL, setpgid(0, PROC_MAX_PROCS + 1));

  // TODO(aoates): this really should be, pgid is a process group without any
  // processes in the current session.
  KTEST_BEGIN("setgpid() pgid doesn't match an existing process group");
  // TODO(aoates): use a better way of finding an unallocated pgid.
  KEXPECT_EQ(-EPERM, setpgid(0, 100));

  KTEST_BEGIN("setgpid() pid isn't self or a child process");
  KEXPECT_EQ(-ESRCH, setpgid(group, proc_current()->id));
  KEXPECT_EQ(-ESRCH, setpgid(group, 0));
  KEXPECT_EQ(-ESRCH, setpgid(100, 0));
  KEXPECT_EQ(-ESRCH, setpgid(-1, group));
  KEXPECT_EQ(-ESRCH, setpgid(PROC_MAX_PROCS + 1, group));

  KEXPECT_EQ(orig_group, getpgid(0));
}

static void child_setgpid_test(void* arg) {
  const pid_t group = (pid_t)arg;
  int test_done = 0;

  // To ensure it's not looked at or carried to children.
  proc_current()->execed = true;

  KTEST_BEGIN("setpgid(): set pgid of child");
  int child = proc_fork(&loop_until_done, &test_done);
  KEXPECT_EQ(0, setpgid(child, group));
  KEXPECT_EQ(group, getpgid(child));
  test_done = 1;
  KEXPECT_EQ(child, proc_wait(0x0));

  KTEST_BEGIN("setpgid(): set pgid of child (with pgid == 0)");
  test_done = 0;
  child = proc_fork(&loop_until_done, &test_done);
  KEXPECT_EQ(0, setpgid(child, 0));
  KEXPECT_EQ(child, getpgid(child));
  test_done = 1;
  KEXPECT_EQ(child, proc_wait(0x0));

  // TODO(aoates): if we ever have good kernel exec() tests, actually test by
  // calling exec() rather than setting the execed bit manually.
  KTEST_BEGIN("setpgid(): set pgid of child that has exec()'d");
  test_done = 0;
  child = proc_fork(&loop_until_done, &test_done);
  KEXPECT_EQ(false, proc_get(child)->execed);
  proc_get(child)->execed = true;
  KEXPECT_EQ(-EACCES, setpgid(child, 0));
  KEXPECT_EQ(proc_current()->pgroup, getpgid(child));

  test_done = 1;
  KEXPECT_EQ(child, proc_wait(0x0));
}

// Create a process group with no leader, then fork a bunch of times and make
// sure the process group id isn't reused.
//
// Note: this test isn't conclusive (depending on the pid allocation strategy it
// could give false negatives), but is good enough for the current pid
// allocation method.
static void dont_reuse_pid_of_group_test(void) {
  int kNumChildren = 5;

  KTEST_BEGIN("fork(): don't use pid of an existing process group");

  // Create a process group with a single non-leader member.
  int parent_done = 0, pgroup_done = 0, test_done = 0;
  const int pgroup_leader_pid = proc_fork(&loop_until_done, &parent_done);
  KEXPECT_EQ(0, setpgid(pgroup_leader_pid, pgroup_leader_pid));
  const int child_pid = proc_fork(&loop_until_done, &pgroup_done);
  KEXPECT_EQ(0, setpgid(child_pid, pgroup_leader_pid));

  parent_done = 1;
  KEXPECT_EQ(pgroup_leader_pid, proc_wait(0x0));

  // Now fork a bunch of times and make sure the parent pid isn't reused.
  for (int i = 0; i < kNumChildren; ++i) {
    const int pid = proc_fork(&loop_until_done, &test_done);
    KEXPECT_NE(pid, pgroup_leader_pid);
  }

  // Now finish the process in the pgroup, and make sure we *do* reuse the
  // pgroup pid.
  pgroup_done = 1;
  KEXPECT_EQ(child_pid, proc_wait(0x0));

  int used_pid = 0;
  for (int i = 0; i < kNumChildren; ++i) {
    const int pid = proc_fork(&loop_until_done, &test_done);
    if (pid == pgroup_leader_pid) used_pid = 1;
  }

  // At least one of the children should have gotten the (now empty) pgroup pid.
  KEXPECT_EQ(1, used_pid);

  test_done = 1;
  for (int i = 0; i < 2 * kNumChildren; ++i) {
    proc_wait(0x0);
  }
}

void proc_group_test(void) {
  KTEST_SUITE_BEGIN("Process group tests");

  int test_done = 0;
  // Create a process that will be it's own group leader that we can use for
  // the tests.
  const int pgroup_leader_pid = proc_fork(&loop_until_done, &test_done);
  KEXPECT_EQ(0, setpgid(pgroup_leader_pid, pgroup_leader_pid));

  basic_getgpid_test();
  fork_and_run(&basic_setgpid_test, pgroup_leader_pid);
  fork_and_run(&invalid_params_setgpid_test, pgroup_leader_pid);
  fork_and_run(&child_setgpid_test, pgroup_leader_pid);
  dont_reuse_pid_of_group_test();

  test_done = 1;
  int child = proc_wait(0x0);
  KEXPECT_EQ(pgroup_leader_pid, child);
}
