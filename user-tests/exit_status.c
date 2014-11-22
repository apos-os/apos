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
#include <unistd.h>
#include <sys/wait.h>

#include "ktest.h"
#include "all_tests.h"

int exit_status_test() {
  KTEST_SUITE_BEGIN("Exit status");

  KTEST_BEGIN("exit() sets status");
  int status = 0;
  pid_t pid;
  if ((pid = fork()) == 0) {
    exit(3);
  }
  KEXPECT_EQ(pid, wait(&status));
  KEXPECT_EQ(3, status);

  KTEST_BEGIN("return from main() sets status");
  if ((pid = fork()) == 0) {
    return 4;
  }
  KEXPECT_EQ(pid, wait(&status));
  KEXPECT_EQ(4, status);

  return 0;
}
