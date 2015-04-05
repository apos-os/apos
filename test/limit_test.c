// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#include "common/errno.h"
#include "proc/fork.h"
#include "proc/limit.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"

static void basic_test(void* arg) {
  KTEST_BEGIN("getrlimit(): initial values");
  for (int i = 0; i < RLIMIT_NUM_RESOURCES; ++i) {
    struct rlimit lim = {0, 0};
    KEXPECT_EQ(0, proc_getrlimit(i, &lim));
    KEXPECT_EQ(RLIM_INFINITY, lim.rlim_cur);
    KEXPECT_EQ(RLIM_INFINITY, lim.rlim_max);
  }

  KTEST_BEGIN("getrlimit(): invalid resource");
  struct rlimit lim;
  KEXPECT_EQ(-EINVAL, proc_getrlimit(-1, &lim));
  KEXPECT_EQ(-EINVAL, proc_getrlimit(-10, &lim));
  KEXPECT_EQ(-EINVAL, proc_getrlimit(RLIMIT_NUM_RESOURCES, &lim));

  KTEST_BEGIN("setrlimit(): basic set");
  lim.rlim_cur = 100;
  lim.rlim_max = 200;
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(100, lim.rlim_cur);
  KEXPECT_EQ(200, lim.rlim_max);

  KTEST_BEGIN("setrlimit(): invalid resource");
  KEXPECT_EQ(-EINVAL, proc_setrlimit(-1, &lim));
  KEXPECT_EQ(-EINVAL, proc_setrlimit(-10, &lim));
  KEXPECT_EQ(-EINVAL, proc_setrlimit(RLIMIT_NUM_RESOURCES, &lim));

  KTEST_BEGIN("setrlimit(): cur > max");
  lim.rlim_cur = 200;
  lim.rlim_max = 200;
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_AS, &lim));
  lim.rlim_cur = 301;
  lim.rlim_max = 300;
  KEXPECT_EQ(-EINVAL, proc_setrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(200, lim.rlim_cur);
  KEXPECT_EQ(200, lim.rlim_max);
}

static void fork_test_child(void* arg) {
  struct rlimit lim = {0, 0};
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(200, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);
}

static void limit_fork_test(void* arg) {
  KTEST_BEGIN("limits: propagated in fork()");
  struct rlimit lim = {200, 300};
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_AS, &lim));
  pid_t child = proc_fork(&fork_test_child, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}

static void limit_perm_test(void* arg) {
  const int kGroupA = 1, kGroupB = 2, kUserA = 3, kUserB = 4;

  KTEST_BEGIN("setrlimit(): non-root can lower max limit");
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));

  struct rlimit lim = {200, 300};
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(200, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);


  KTEST_BEGIN("setrlimit(): non-root can raise soft limit");
  lim.rlim_cur = 250;
  lim.rlim_max = 300;
  KEXPECT_EQ(0, proc_setrlimit(RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(250, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);


  KTEST_BEGIN("setrlimit(): non-root can't raise max limit");
  lim.rlim_cur = 220;
  lim.rlim_max = 350;
  KEXPECT_EQ(-EPERM, proc_setrlimit(RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(RLIMIT_AS, &lim));
  KEXPECT_EQ(250, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);
}

void limit_test(void) {
  KTEST_SUITE_BEGIN("process limit tests");

  KEXPECT_GE(proc_fork(&basic_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_fork_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_perm_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);
}
