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
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "test/kernel_tests.h"

static void do_nothing(void* arg) {
  proc_exit(1);
}

static void basic_waitpid_test(void) {
  KTEST_BEGIN("waitpid(): basic child test");
  pid_t child = proc_fork(&do_nothing, NULL);
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
  ksleep(1000);
}

static void do_nothing_sig(int sig) {}

static void interruptable_helper(void* arg) {
  struct sigaction act = {&do_nothing_sig, 0, 0};
  KEXPECT_EQ(0, proc_sigaction(SIGUSR1, &act, NULL));
  pid_t sleeper = proc_fork(&sleep_func, NULL);
  const uint32_t start = get_time_ms();
  int result;
  if ((int)arg)
    result = proc_waitpid(-1, NULL, 0);
  else
    result = proc_wait(NULL);
  KEXPECT_EQ(0, proc_kill(sleeper, SIGKILL));
  KEXPECT_EQ(-EINTR, result);
  const uint32_t end = get_time_ms();
  KEXPECT_LE(end - start, 200);
}

static void interruptable_waitpid_test(void) {
  KTEST_BEGIN("wait(): interrupted by signal");
  pid_t waiter = proc_fork(&interruptable_helper, (void*)0);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(0, proc_kill(waiter, SIGUSR1));
  KEXPECT_EQ(waiter, proc_wait(NULL));


  KTEST_BEGIN("waitpid(): interrupted by signal");
  waiter = proc_fork(&interruptable_helper, (void*)1);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(0, proc_kill(waiter, SIGUSR1));
  KEXPECT_EQ(waiter, proc_wait(NULL));
}

void wait_test(void) {
  KTEST_SUITE_BEGIN("wait() and waitpid() tests");
  basic_waitpid_test();
  interruptable_waitpid_test();
}
