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

static void fork_test_func2(void* arg) {
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserB, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupB, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);
}

static void fork_test_func(void* arg) {
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->ruid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->euid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->suid);

  KEXPECT_EQ(SUPERUSER_GID, proc_current()->rgid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->egid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->sgid);

  proc_current()->ruid = kTestUserA;
  proc_current()->euid = kTestUserB;
  proc_current()->suid = kTestUserC;

  proc_current()->rgid = kTestGroupA;
  proc_current()->egid = kTestGroupB;
  proc_current()->sgid = kTestGroupC;

  pid_t child_pid = proc_fork(&fork_test_func2, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_wait(0x0);
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

static void seteuid_test_func(void* arg) {
  KTEST_BEGIN("seteuid() as superuser");
  KEXPECT_EQ(SUPERUSER_UID, geteuid());
  KEXPECT_EQ(SUPERUSER_GID, getegid());

  KEXPECT_EQ(0, seteuid(kTestUserA));
  KEXPECT_EQ(kTestUserA, geteuid());
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->ruid);
  KEXPECT_EQ(kTestUserA, proc_current()->euid);
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->suid);

  KTEST_BEGIN("setegid() as superuser");
  KEXPECT_EQ(SUPERUSER_GID, getegid());

  KEXPECT_EQ(0, setegid(kTestGroupA));
  KEXPECT_EQ(kTestUserA, geteuid());
  KEXPECT_EQ(kTestGroupA, getegid());
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupA, proc_current()->egid);
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->sgid);

  // Manually twiddle the effective and saved uid/gid for the tests.
  proc_current()->ruid = kTestUserA;
  proc_current()->rgid = kTestGroupA;
  proc_current()->euid = kTestUserB;
  proc_current()->egid = kTestGroupB;
  proc_current()->suid = kTestUserC;
  proc_current()->sgid = kTestGroupC;

  KTEST_BEGIN("geteuid() returns effective uid");
  KEXPECT_EQ(kTestUserB, geteuid());

  KTEST_BEGIN("getegid() returns effective gid");
  KEXPECT_EQ(kTestGroupB, getegid());

  KTEST_BEGIN("seteuid() as non-superuser to real uid");
  KEXPECT_EQ(0, seteuid(kTestUserA));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserA, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setegid() as non-superuser to real gid");
  KEXPECT_EQ(0, setegid(kTestGroupA));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupA, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);

  KTEST_BEGIN("seteuid() as non-superuser to saved uid");
  KEXPECT_EQ(0, seteuid(kTestUserC));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserC, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setegid() as non-superuser to saved gid");
  KEXPECT_EQ(0, setegid(kTestGroupC));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupC, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);

  KTEST_BEGIN("seteuid() as non-superuser to unrelated uid");
  KEXPECT_EQ(-EPERM, seteuid(kTestUserD));
  KEXPECT_EQ(-EPERM, seteuid(SUPERUSER_UID));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserC, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setegid() as non-superuser to unrelated gid");
  KEXPECT_EQ(-EPERM, setegid(kTestGroupD));
  KEXPECT_EQ(-EPERM, setegid(SUPERUSER_GID));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupC, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);
}

static void seteuid_test(void) {
  pid_t child_pid = proc_fork(&seteuid_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_wait(0x0);
}

static void setreuid_test_func(void* arg) {
  KTEST_BEGIN("setreuid() as superuser");
  KEXPECT_EQ(SUPERUSER_UID, getuid());
  KEXPECT_EQ(SUPERUSER_GID, getgid());

  KEXPECT_EQ(0, setreuid(kTestUserA, kTestUserB));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserB, proc_current()->euid);
  KEXPECT_EQ(kTestUserB, proc_current()->suid);

  KTEST_BEGIN("setregid() as superuser");
  KEXPECT_EQ(SUPERUSER_GID, getgid());

  KEXPECT_EQ(0, setregid(kTestGroupA, kTestGroupB));
  KEXPECT_EQ(kTestUserA, getuid());
  KEXPECT_EQ(kTestGroupA, getgid());
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupB, proc_current()->egid);
  KEXPECT_EQ(kTestGroupB, proc_current()->sgid);

  proc_current()->ruid = SUPERUSER_UID;
  proc_current()->rgid = SUPERUSER_GID;
  proc_current()->euid = kTestUserC;
  proc_current()->egid = kTestGroupC;

  KTEST_BEGIN("setreuid() as superuser (just real)");
  KEXPECT_EQ(0, setreuid(kTestUserA, -1));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserC, proc_current()->euid);
  KEXPECT_EQ(kTestUserC, proc_current()->suid);

  KTEST_BEGIN("setregid() as superuser (just real)");
  KEXPECT_EQ(0, setregid(kTestGroupA, -1));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupC, proc_current()->egid);
  KEXPECT_EQ(kTestGroupC, proc_current()->sgid);

  proc_current()->ruid = SUPERUSER_UID;
  proc_current()->rgid = SUPERUSER_GID;
  proc_current()->euid = kTestUserB;
  proc_current()->egid = kTestGroupB;

  KTEST_BEGIN("setreuid() as superuser (just effective)");
  KEXPECT_EQ(0, setreuid(-1, kTestUserA));
  KEXPECT_EQ(SUPERUSER_UID, proc_current()->ruid);
  KEXPECT_EQ(kTestUserA, proc_current()->euid);
  KEXPECT_EQ(kTestUserA, proc_current()->suid);

  KTEST_BEGIN("setregid() as superuser (just effective)");
  KEXPECT_EQ(0, setregid(-1, kTestGroupA));
  KEXPECT_EQ(SUPERUSER_GID, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupA, proc_current()->egid);
  KEXPECT_EQ(kTestGroupA, proc_current()->sgid);

  // Manually twiddle the effective and saved uid/gid for the tests.
  proc_current()->ruid = kTestUserA;
  proc_current()->rgid = kTestGroupA;
  proc_current()->euid = kTestUserB;
  proc_current()->egid = kTestGroupB;
  proc_current()->suid = kTestUserC;
  proc_current()->sgid = kTestGroupC;

  KTEST_BEGIN("setreuid() as non-superuser effective to effective uid");
  KEXPECT_EQ(0, setreuid(-1, kTestUserB));

  KTEST_BEGIN("setregid() as non-superuser effective to effective gid");
  KEXPECT_EQ(0, setregid(-1, kTestGroupB));

  KTEST_BEGIN("setreuid() as non-superuser real to real uid");
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(0, setreuid(kTestUserA, -1));

  KTEST_BEGIN("setreuid() as non-superuser real to effective uid");
  KEXPECT_EQ(-EPERM, setreuid(kTestUserB, -1));

  KTEST_BEGIN("setreuid() as non-superuser real to saved uid");
  KEXPECT_EQ(-EPERM, setreuid(kTestUserC, -1));

  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserB, proc_current()->euid);
  KEXPECT_EQ(kTestUserB, proc_current()->suid);

  KTEST_BEGIN("setregid() as non-superuser real to real gid");
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(0, setregid(kTestGroupA, -1));

  KTEST_BEGIN("setregid() as non-superuser real to effective gid");
  KEXPECT_EQ(-EPERM, setregid(kTestGroupB, -1));

  KTEST_BEGIN("setregid() as non-superuser real to saved gid");
  KEXPECT_EQ(-EPERM, setregid(kTestGroupC, -1));

  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupB, proc_current()->egid);
  KEXPECT_EQ(kTestGroupB, proc_current()->sgid);

  KTEST_BEGIN("setreuid() as non-superuser effective to real uid");
  KEXPECT_EQ(0, setreuid(-1, kTestUserA));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserA, proc_current()->euid);
  KEXPECT_EQ(kTestUserB, proc_current()->suid);

  KTEST_BEGIN("setregid() as non-superuser effective to real gid");
  KEXPECT_EQ(0, setregid(-1, kTestGroupA));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupA, proc_current()->egid);
  KEXPECT_EQ(kTestGroupB, proc_current()->sgid);

  KTEST_BEGIN("setreuid() as non-superuser effective to saved uid");
  KEXPECT_EQ(0, setreuid(-1, kTestUserB));
  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserB, proc_current()->euid);
  KEXPECT_EQ(kTestUserB, proc_current()->suid);

  KTEST_BEGIN("setregid() as non-superuser effective to saved gid");
  KEXPECT_EQ(0, setregid(-1, kTestGroupB));
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupB, proc_current()->egid);
  KEXPECT_EQ(kTestGroupB, proc_current()->sgid);

  KTEST_BEGIN("setreuid() as non-superuser effective to unrelated uid");
  KEXPECT_EQ(-EPERM, setreuid(-1, kTestUserD));
  KEXPECT_EQ(-EPERM, setreuid(-1, SUPERUSER_UID));

  KTEST_BEGIN("setregid() as non-superuser effective to unrelated gid");
  KEXPECT_EQ(-EPERM, setregid(-1, kTestGroupD));
  KEXPECT_EQ(-EPERM, setregid(-1, SUPERUSER_GID));

  // The following two test that nothing is updated when the euid/egid would be
  // allowed, but the ruid/rgid shouldn't be.
  KTEST_BEGIN("setreuid() as non-superuser real to unrelated uid");
  KEXPECT_EQ(-EPERM, setreuid(kTestUserD, kTestUserC));

  KTEST_BEGIN("setregid() as non-superuser real to unrelated gid");
  KEXPECT_EQ(-EPERM, setregid(kTestUserD, kTestGroupC));

  KEXPECT_EQ(kTestUserA, proc_current()->ruid);
  KEXPECT_EQ(kTestUserB, proc_current()->euid);
  KEXPECT_EQ(kTestUserB, proc_current()->suid);
  KEXPECT_EQ(kTestGroupA, proc_current()->rgid);
  KEXPECT_EQ(kTestGroupB, proc_current()->egid);
  KEXPECT_EQ(kTestGroupB, proc_current()->sgid);
}

static void setreuid_test(void) {
  pid_t child_pid = proc_fork(&setreuid_test_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  proc_wait(0x0);
}

void user_test(void) {
  KTEST_SUITE_BEGIN("kthread_test");

  root_test();
  fork_test();
  setuid_test();
  seteuid_test();
  setreuid_test();
}
