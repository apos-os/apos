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

// Tests for process user and group identity.
#include <stdint.h>

#include "common/kassert.h"
#include "proc/fork.h"
#include "proc/process.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"

static void root_test(void) {
  KTEST_BEGIN("Running as root test");

  KEXPECT_EQ(SUPERUSER_UID, proc_current()->ruid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->euid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->suid);

  KEXPECT_EQ(SUPERUSER_GID, proc_current()->rgid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->egid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->sgid);
}

static void fork_test_func(void* arg) {
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->ruid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->euid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->suid);

  KEXPECT_EQ(SUPERUSER_GID, proc_current()->rgid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->egid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->sgid);
}

static void fork_test(void) {
  KTEST_BEGIN("Identity preserved across fork() test");

  // Fork.
  pid_t child_pid = proc_fork(&fork_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_wait(0x0);
}

// TODO(aoates): test that the various identity bits are copied correctly (with
// different values for each)

void user_test(void) {
  KTEST_SUITE_BEGIN("kthread_test");

  root_test();
  fork_test();
}
