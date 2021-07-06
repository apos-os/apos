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
#include <fcntl.h>
#include <signal.h>

#include "ktest.h"
#include "all_tests.h"

bool run_slow_tests = false;

int main(int argc, char** argv) {
  if (strcmp(argv[0], "execve_test_helper") == 0)
    return execve_helper(argc, argv);

  if (argc > 1 && strcmp(argv[1], "all") == 0)
    run_slow_tests = true;

  // Some of the tests rely on these signals, so ensure they're enabled.
  sigset_t mask;
  sigemptyset(&mask);
  sigprocmask(SIG_SETMASK, &mask, NULL);
  signal(SIGTTIN, SIG_DFL);
  signal(SIGTTOU, SIG_DFL);
  signal(SIGTSTP, SIG_DFL);

  ktest_begin_all();

  syscall_errno_test();
  int status = exit_status_test();
  if (status) return status;

  basic_signal_test();
  execve_test();
  stop_test();
  wait_test();
  fs_test();
  misc_syscall_test();
  socket_test();
  setjmp_test();
  cpu_exception_test();

  return ktest_finish_all();
}
