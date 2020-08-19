// Copyright 2020 Andrew Oates.  All Rights Reserved.
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

#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/wait.h"

static void run_tests_func(void* arg) {
  char* const argv[] = {"/bin/all_tests", NULL};
  char* const envp[] = {NULL};
  int result = do_execve("/bin/all_tests", argv, envp, NULL, NULL);
  // If the exec is successful, we won't ever reach here anyway.
  KEXPECT_EQ(0, result);
}

// A stub kernel test that simply runs the user test binary (if present) and
// passes if it passes.
void run_user_tests(void) {
  KTEST_SUITE_BEGIN("user-mode tests");
  KTEST_BEGIN("user-mode tests");
  kpid_t child_pid = proc_fork(&run_tests_func, 0x0);
  KEXPECT_GE(child_pid, 0);

  int exit_status;
  KEXPECT_EQ(child_pid, proc_waitpid(child_pid, &exit_status, 0));
  KEXPECT_EQ(0, exit_status);
}
