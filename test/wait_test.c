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

#include "proc/wait.h"

#include "proc/exit.h"
#include "proc/fork.h"
#include "proc/group.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "test/kernel_tests.h"
#include "user/include/apos/wait.h"

static void do_nothing(void* arg) {
  proc_exit(1);
}

static void basic_waitpid_test(void) {
  KTEST_BEGIN("waitpid(): basic child test");
  kpid_t child = proc_fork(&do_nothing, NULL);
  int status;
  KEXPECT_EQ(child, proc_waitpid(-1, &status, 0));
  KEXPECT_EQ(1, status);

  KTEST_BEGIN("waitpid(): NULL status pointer test");
  child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(child, proc_waitpid(-1, NULL, 0));

  KTEST_BEGIN("waitpid(): pid > 0 invalid test");
  KEXPECT_EQ(-ECHILD, proc_waitpid(1, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(PROC_MAX_PROCS, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(PROC_MAX_PROCS + 1, NULL, 0));

  KTEST_BEGIN("waitpid(): pid == 0 invalid test");
  KEXPECT_EQ(-ECHILD, proc_waitpid(0, NULL, 0));

  KTEST_BEGIN("waitpid(): pid < -1 invalid test");
  KEXPECT_EQ(-ECHILD, proc_waitpid(-2, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(-PROC_MAX_PROCS, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(-PROC_MAX_PROCS - 1, NULL, 0));

  KTEST_BEGIN("waitpid(): invalid flags test");
  KEXPECT_EQ(-EINVAL, proc_waitpid(-1, NULL, 100));
  KEXPECT_EQ(-EINVAL, proc_waitpid(-1, NULL, -100));
}

static void sleep_func(void* arg) {
  ksleep(arg ? (intptr_t)arg : 1000);
}

static void do_nothing_sig(int sig) {}

static void interruptable_helper(void* arg) {
  struct ksigaction act = {&do_nothing_sig, 0, 0};
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &act, NULL));
  kpid_t sleeper = proc_fork(&sleep_func, NULL);
  const apos_ms_t start = get_time_ms();
  int result;
  if ((intptr_t)arg)
    result = proc_waitpid(-1, NULL, 0);
  else
    result = proc_wait(NULL);
  KEXPECT_EQ(0, proc_kill(sleeper, SIGKILL));
  KEXPECT_EQ(-EINTR, result);
  const apos_ms_t end = get_time_ms();
  KEXPECT_LE(end - start, 200);
}

static void interruptable_waitpid_test(void) {
  KTEST_BEGIN("wait(): interrupted by signal");
  kpid_t waiter = proc_fork(&interruptable_helper, (void*)0);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(0, proc_kill(waiter, SIGUSR1));
  KEXPECT_EQ(waiter, proc_wait(NULL));


  KTEST_BEGIN("waitpid(): interrupted by signal");
  waiter = proc_fork(&interruptable_helper, (void*)1);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(0, proc_kill(waiter, SIGUSR1));
  KEXPECT_EQ(waiter, proc_wait(NULL));
}

static void do_fork(void* arg) {
  *(kpid_t*)arg = proc_fork(&sleep_func, NULL);
}

// Send a signal to the process then wait until it's exited and cleaned up.
// There's no proper way to do this with POSIX semantics.
static void cleanup_grandchild(kpid_t grandchild) {
  KEXPECT_EQ(0, proc_kill(grandchild, SIGKILL));
  apos_ms_t start = get_time_ms();
  while (proc_get(grandchild)) {
    ksleep(10);
  }
  klogf("cleanup of grandchild %d took %d ms...\n", grandchild,
        get_time_ms() - start);
}

static void wait_for_specific_pid_test(void) {
  KTEST_BEGIN("waitpid(): invalid pid (no process with that pid)");
  kpid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
  KEXPECT_EQ(-ECHILD, proc_waitpid(child, NULL, 0));


  KTEST_BEGIN("waitpid(): invalid pid (process exists but isn't a child)");
  kpid_t grandchild = 0;
  child = proc_fork(&do_fork, &grandchild);
  KEXPECT_EQ(child, proc_wait(NULL));

  KEXPECT_NE(NULL, proc_get(grandchild));
  KEXPECT_EQ(PROC_RUNNING, proc_state(grandchild));
  KEXPECT_EQ(-ECHILD, proc_waitpid(grandchild, NULL, 0));
  cleanup_grandchild(grandchild);


  KTEST_BEGIN("waitpid(): pid is child (already stopped)");
  child = proc_fork(&do_nothing, NULL);
  for (int i = 0; i < 5 && proc_state(child) == PROC_RUNNING; ++i)
    scheduler_yield();
  int status = 5;
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  KEXPECT_EQ(1, status);


  KTEST_BEGIN("waitpid(): pid is child (not yet stopped)");
  child = proc_fork(&sleep_func, (void*)100);
  status = 5;
  apos_ms_t start_ms = get_time_ms();
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  apos_ms_t end_ms = get_time_ms();
  KEXPECT_EQ(0, status);
  KEXPECT_GE(end_ms - start_ms, 30);


  KTEST_BEGIN("waitpid(): multiple children (child is stopped)");
  child = proc_fork(&sleep_func, (void*)50);
  kpid_t childB = proc_fork(&do_nothing, NULL);
  kpid_t childC = proc_fork(&do_nothing, NULL);
  kpid_t childD = proc_fork(&sleep_func, (void*)50);
  for (int i = 0; i < 5 && proc_state(childC) == PROC_RUNNING; ++i)
    scheduler_yield();
  status = 5;
  KEXPECT_EQ(childC, proc_waitpid(childC, &status, 0));
  KEXPECT_EQ(1, status);
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));
  KEXPECT_EQ(childB, proc_waitpid(childB, NULL, 0));
  KEXPECT_EQ(childD, proc_waitpid(childD, NULL, 0));

  KTEST_BEGIN("waitpid(): multiple children (child is not stopped)");
  child = proc_fork(&sleep_func, (void*)50);
  childB = proc_fork(&do_nothing, NULL);
  childC = proc_fork(&sleep_func, (void*)50);
  childD = proc_fork(&do_nothing, NULL);
  for (int i = 0; i < 5 && proc_state(childC) == PROC_RUNNING; ++i)
    scheduler_yield();
  status = 5;
  start_ms = get_time_ms();
  KEXPECT_EQ(childC, proc_waitpid(childC, &status, 0));
  end_ms = get_time_ms();
  KEXPECT_EQ(0, status);
  KEXPECT_GE(end_ms - start_ms, 20);
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));
  KEXPECT_EQ(childB, proc_waitpid(childB, NULL, 0));
  KEXPECT_EQ(childD, proc_waitpid(childD, NULL, 0));
}

static void create_children_in_group(void* arg) {
  kpid_t child = proc_fork(&sleep_func, (void*)500);
  KEXPECT_EQ(0, setpgid(child, child));
  *(kpid_t*)arg = child;
}

static void do_proc_change_pgroup_test(void* arg);
static void wait_for_pgroup_test(void) {
  KTEST_BEGIN("waitpid(): wait for non-existant process group");
  kpid_t child = proc_fork(&do_nothing, NULL);
  KEXPECT_EQ(-ECHILD, proc_waitpid(-child, NULL, 0));
  KEXPECT_EQ(child, proc_wait(NULL));

  KEXPECT_EQ(-ECHILD, proc_waitpid(-PROC_MAX_PROCS, NULL, 0));


  KTEST_BEGIN("waitpid(): process group exists but has no children");
  kpid_t grandchild;
  child = proc_fork(&create_children_in_group, &grandchild);
  KEXPECT_EQ(child, proc_wait(NULL));

  KEXPECT_EQ(-ECHILD, proc_waitpid(-grandchild, NULL, 0));
  cleanup_grandchild(grandchild);


  KTEST_BEGIN("waitpid(): process group with stopped children");
  child = proc_fork(&create_children_in_group, &grandchild);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&do_nothing, NULL);
  kpid_t childB = proc_fork(&do_nothing, NULL);
  kpid_t childC = proc_fork(&sleep_func, (void*)50);
  KEXPECT_EQ(0, setpgid(child, grandchild));
  KEXPECT_EQ(0, setpgid(childB, grandchild));
  KEXPECT_EQ(0, setpgid(childC, grandchild));
  while (proc_state(child) == PROC_RUNNING &&
         proc_state(childB) == PROC_RUNNING)
    scheduler_yield();
  KEXPECT_EQ(PROC_RUNNING, proc_state(childC));
  apos_ms_t start_ms = get_time_ms();
  kpid_t waitres1 = proc_waitpid(-grandchild, NULL, 0);
  kpid_t waitres2 = proc_waitpid(-grandchild, NULL, 0);
  apos_ms_t end_ms = get_time_ms();
  KEXPECT_GE(waitres1, 0);
  KEXPECT_GE(waitres2, 0);
  KEXPECT_EQ(1, waitres1 == child || waitres1 == childB);
  KEXPECT_EQ(1, waitres2 == child || waitres2 == childB);
  KEXPECT_LE(end_ms - start_ms, 50);
  KEXPECT_EQ(childC, proc_waitpid(-grandchild, NULL, 0));
  cleanup_grandchild(grandchild);


  KTEST_BEGIN("waitpid(): process group with running children");
  child = proc_fork(&create_children_in_group, &grandchild);
  KEXPECT_EQ(child, proc_wait(NULL));

  child = proc_fork(&do_nothing, NULL);
  childB = proc_fork(&sleep_func, (void*)20);
  childC = proc_fork(&sleep_func, (void*)40);
  KEXPECT_EQ(0, setpgid(childB, grandchild));
  KEXPECT_EQ(0, setpgid(childC, grandchild));
  start_ms = get_time_ms();
  KEXPECT_EQ(childB, proc_waitpid(-grandchild, NULL, 0));
  KEXPECT_EQ(childC, proc_waitpid(-grandchild, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(-grandchild, NULL, 0));
  KEXPECT_EQ(child, proc_waitpid(-1, NULL, 0));
  end_ms = get_time_ms();
  KEXPECT_GE(end_ms - start_ms, 20);
  cleanup_grandchild(grandchild);


  KTEST_BEGIN("waitpid(): waitpid(0) current process group");
  child = proc_fork(&do_nothing, NULL);
  childB = proc_fork(&do_nothing, NULL);
  childC = proc_fork(&sleep_func, (void*)20);
  kpid_t childD = proc_fork(&sleep_func, (void*)20);
  KEXPECT_EQ(getpgid(0), getpgid(child));
  KEXPECT_EQ(getpgid(0), getpgid(childB));
  KEXPECT_EQ(getpgid(0), getpgid(childC));
  KEXPECT_EQ(0, setpgid(childD, childD));
  waitres1 = proc_waitpid(0, NULL, 0);
  waitres2 = proc_waitpid(0, NULL, 0);
  KEXPECT_EQ(1, waitres1 == child || waitres1 == childB);
  KEXPECT_EQ(1, waitres2 == child || waitres2 == childB);
  KEXPECT_EQ(0, proc_waitpid(0, NULL, WNOHANG));
  KEXPECT_EQ(childC, proc_waitpid(0, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(0, NULL, 0));
  KEXPECT_EQ(childD, proc_waitpid(childD, NULL, 0));


  KTEST_BEGIN("waitpid(): waitpid(0) current process group changes while blocking");
  child = proc_fork(&do_proc_change_pgroup_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}

typedef struct {
  notification_t proc1_go;
  notification_t proc2_go;
  notification_t proc3_go;
  kpid_t target_group;
} proc_change_test_state_t;

static void* proc_group_change_test_thread(void* arg) {
  proc_change_test_state_t* state = (proc_change_test_state_t*)arg;
  ksleep(10);  // Wait for the main thread to get into its blocking call.
  KEXPECT_EQ(0, setpgid(0, state->target_group));
  ntfn_notify(&state->proc1_go);
  ksleep(10);  // Give the first thread a chance to (erroneously) wake up.
  ntfn_notify(&state->proc2_go);  // waitpid() should now return the second.
  ksleep(10);
  ntfn_notify(&state->proc3_go);  // waitpid() should now return the second.
  return NULL;
}

static void exit_after_nftn(void* arg) {
  notification_t* ntfn = (notification_t*)arg;
  KEXPECT_TRUE(ntfn_await_with_timeout(ntfn, 5000));
  proc_exit(0);
}

static void do_proc_change_pgroup_test(void* arg) {
  // Launch three children.  The first stays in our process group.  The second,
  // make a process group leader.  The third goes in the second's process group.
  // They should all sleep.  We go into a blocking waitpid() call.  While we
  // block, another thread in our process changes our process group to the
  // second process's group, then wakes up the first thread.  Our waitpid()
  // should continue to block.  Once once we wake up the second and third
  // threads should waitpid return.
  proc_change_test_state_t state;
  ntfn_init(&state.proc1_go);
  ntfn_init(&state.proc2_go);
  ntfn_init(&state.proc3_go);
  kpid_t child = proc_fork(&exit_after_nftn, &state.proc1_go);
  kpid_t childB = proc_fork(&exit_after_nftn, &state.proc2_go);
  kpid_t childC = proc_fork(&exit_after_nftn, &state.proc3_go);
  KEXPECT_EQ(0, setpgid(childB, childB));
  KEXPECT_EQ(0, setpgid(childC, childB));
  state.target_group = childB;

  // Launch the disruptor thread.
  kthread_t thread;
  KEXPECT_EQ(
      0, proc_thread_create(&thread, &proc_group_change_test_thread, &state));

  // This call will start with our pgroup == original_pgroup (same as child),
  // but should go to sleep, and then wake up with our pgroup == childB.  It
  // should only return childB or childC.
  KEXPECT_EQ(childB, proc_waitpid(0, NULL, 0));
  KEXPECT_EQ(childC, proc_waitpid(0, NULL, 0));
  KEXPECT_EQ(-ECHILD, proc_waitpid(0, NULL, 0));
  KEXPECT_EQ(child, proc_waitpid(child, NULL, 0));

  KEXPECT_EQ(NULL, kthread_join(thread));
}

static void wait_guid_test(void) {
  KTEST_BEGIN("proc_wait_guid(): process exits");
  notification_t ntfn;
  ntfn_init(&ntfn);

  kpid_t child = proc_fork(&exit_after_nftn, &ntfn);
  uint32_t guid = proc_get_procguid(child);
  ntfn_notify(&ntfn);
  KEXPECT_EQ(child, proc_wait(NULL));
  apos_ms_t start = get_time_ms();
  KEXPECT_EQ(0, proc_wait_guid(child, guid, 5000));
  KEXPECT_LT(get_time_ms() - start, 2000);
  start = get_time_ms();
  KEXPECT_EQ(0, proc_wait_guid(child, guid, 5000));
  KEXPECT_LT(get_time_ms() - start, 500);
  start = get_time_ms();
  KEXPECT_EQ(0, proc_wait_guid(child, 1234, 5000));
  KEXPECT_LT(get_time_ms() - start, 500);


  KTEST_BEGIN("proc_wait_guid(): process exits AND is replaced");
  ntfn_init(&ntfn);
  child = proc_fork(&exit_after_nftn, &ntfn);
  guid = proc_get_procguid(child);
  ntfn_notify(&ntfn);
  KEXPECT_EQ(child, proc_wait(NULL));

  // This is racey :/
  ntfn_init(&ntfn);
  kpid_t child2 = proc_fork(&exit_after_nftn, &ntfn);
  KEXPECT_EQ(child, child2);
  KEXPECT_NE(guid, proc_get_procguid(child2));
  start = get_time_ms();
  KEXPECT_EQ(0, proc_wait_guid(child, guid, 5000));
  KEXPECT_LT(get_time_ms() - start, 500);
  ntfn_notify(&ntfn);
  KEXPECT_EQ(child2, proc_wait(NULL));


  KTEST_BEGIN("proc_wait_guid(): times out");
  ntfn_init(&ntfn);
  child = proc_fork(&exit_after_nftn, &ntfn);
  guid = proc_get_procguid(child);
  start = get_time_ms();
  KEXPECT_EQ(-ETIMEDOUT, proc_wait_guid(child, guid, 100));
  KEXPECT_GE(get_time_ms() - start, 100);
  KEXPECT_LT(get_time_ms() - start, 2000);
  ntfn_notify(&ntfn);
  KEXPECT_EQ(child, proc_wait(NULL));
}

void do_wait_test(void* arg) {
  basic_waitpid_test();
  interruptable_waitpid_test();
  wait_for_specific_pid_test();
  wait_for_pgroup_test();
  wait_guid_test();
}

void do_wait_test_outer(void* arg) {
  KEXPECT_EQ(0, setpgid(0, 0));  // Make ourselves the process group leader.
  kpid_t child = proc_fork(&do_wait_test, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}

void wait_test(void) {
  KTEST_SUITE_BEGIN("wait() and waitpid() tests");
  // We fork twice to do the actual tests.  This lets us ensure,
  // 1) we have a process group ID that is not 1 (otherwise passing -1 to
  //    waitpid is ambiguous), and
  // 2) we (the process running the tests) are not the process group leader, to
  //    test that we're looking for process with the same process group as us,
  //    not _in_ our process group.
  kpid_t child = proc_fork(&do_wait_test_outer, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}
