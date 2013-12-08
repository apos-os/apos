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

// TODO(aoates): test getpgid() across sessions once we have session support.

void proc_group_test(void) {
  KTEST_SUITE_BEGIN("Process group tests");

  basic_getgpid_test();
}
