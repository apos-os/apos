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

const int kTestUserA = 5001;
const int kTestUserB = 5002;
const int kTestUserC = 5003;
const int kTestUserD = 5004;
const int kTestGroupA = 6001;
const int kTestGroupB = 6002;
const int kTestGroupC = 6003;
const int kTestGroupD = 6004;

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

// Fork before we do any setuid tests so that we don't lose our root
// privileges.
static void setuid_test_func(void* arg) {
  KTEST_BEGIN("setuid() as superuser");
  KEXPECT_EQ(SUPERUSER_UID, getuid());
  KEXPECT_EQ(SUPERUSER_GID, getgid());

  KEXPECT_EQ(0, setuid(kTestUserA));
  KEXPECT_EQ(kTestUserA, getuid());
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserA, proc_current()->euid);
  KEXPECT_EQ(kTestUserA, proc_current()->suid);

  KTEST_BEGIN("setgid() as superuser");
  KEXPECT_EQ(SUPERUSER_GID, getgid());

  KEXPECT_EQ(0, setgid(kTestGroupA));
  KEXPECT_EQ(kTestUserA, getuid());
  KEXPECT_EQ(kTestGroupA, getgid());
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupA, proc_current()->egid);
  KEXPECT_EQ(kTestGroupA, proc_current()->sgid);

  // Manually twiddle the effective and saved uid/gid for the tests.
  proc_current()->euid = kTestUserB;
  proc_current()->egid = kTestGroupB;
  proc_current()->suid = kTestUserC;
  proc_current()->sgid = kTestGroupC;

  KTEST_BEGIN("getuid() returns real uid");
  KEXPECT_EQ(kTestUserA, getuid());

  KTEST_BEGIN("getgid() returns real gid");
  KEXPECT_EQ(kTestGroupA, getgid());

  KTEST_BEGIN("setuid() as non-superuser to real uid");
  KEXPECT_EQ(0, setuid(kTestUserA));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserA, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setgid() as non-superuser to real gid");
  KEXPECT_EQ(0, setgid(kTestGroupA));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupA, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);

  KTEST_BEGIN("setuid() as non-superuser to saved uid");
  KEXPECT_EQ(0, setuid(kTestUserC));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserC, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setgid() as non-superuser to saved gid");
  KEXPECT_EQ(0, setgid(kTestGroupC));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupC, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);

  KTEST_BEGIN("setuid() as non-superuser to unrelated uid");
  KEXPECT_EQ(-EPERM, setuid(kTestUserD));
  KEXPECT_EQ(-EPERM, setuid(SUPERUSER_UID));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserC, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setgid() as non-superuser to unrelated gid");
  KEXPECT_EQ(-EPERM, setgid(kTestGroupD));
  KEXPECT_EQ(-EPERM, setgid(SUPERUSER_GID));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupC, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);
}

static void setuid_test(void) {
  pid_t child_pid = proc_fork(&setuid_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_wait(0x0);
}

// TODO(aoates): test that the various identity bits are copied correctly (with
// different values for each)

void user_test(void) {
  KTEST_SUITE_BEGIN("kthread_test");

  root_test();
  fork_test();
  setuid_test();
}
