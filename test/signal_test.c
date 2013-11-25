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
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "test/ktest.h"

static void ksigemptyset_test(void) {
  KTEST_BEGIN("ksigemptyset() test");

  sigset_t set;
  KEXPECT_EQ(0, ksigemptyset(&set));

  for (int i = SIGMIN; i <= SIGMAX; ++i) {
    KEXPECT_EQ(0, ksigismember(&set, i));
  }
}

static void ksigfillset_test(void) {
  KTEST_BEGIN("ksigfillset() test");

  sigset_t set;
  KEXPECT_EQ(0, ksigfillset(&set));

  for (int i = SIGMIN; i <= SIGMAX; ++i) {
    KEXPECT_EQ(1, ksigismember(&set, i));
  }
}

static void ksigaddset_test(void) {
  KTEST_BEGIN("ksigaddset() test");

  sigset_t set;
  ksigemptyset(&set);

  KEXPECT_EQ(0, ksigaddset(&set, SIGABRT));

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
  KEXPECT_EQ(-EINVAL, proc_kill(-10, SIGABRT));
  // TODO(aoates): figure out a better way to generate a guaranteed-unused PID.
  KEXPECT_EQ(-EINVAL, proc_kill(100, SIGABRT));
  KEXPECT_EQ(-EINVAL, proc_kill(PROC_MAX_PROCS + 10, SIGABRT));

  // TODO(aoates): test with a zombie process.

  KTEST_BEGIN("proc_kill() invalid signal test");
  KEXPECT_EQ(-EINVAL, proc_kill(my_pid, -1));
  KEXPECT_EQ(-EINVAL, proc_kill(my_pid, SIGMAX + 1));

  KTEST_BEGIN("proc_kill() SIGNULL test");
  KEXPECT_EQ(0, proc_kill(my_pid, 0));
  KEXPECT_EQ(-EINVAL, proc_kill(PROC_MAX_PROCS + 10, 0));

  // TODO(aoates): test the actual kill functionality.
}

void signal_test(void) {
  KTEST_SUITE_BEGIN("signals");

  ksigemptyset_test();
  ksigfillset_test();
  ksigaddset_test();
  ksigdelset_test();
  ksigismember_test();

  kill_test();
}
