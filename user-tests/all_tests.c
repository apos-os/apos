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

#include "ktest.h"
#include "all_tests.h"

int main(int argc, char** argv) {
  const char* tty = "/dev/tty0";
  if (argc > 1) tty = argv[1];
  open(tty, O_RDONLY);
  open(tty, O_WRONLY);
  open(tty, O_WRONLY);

  ktest_begin_all();

  syscall_errno_test();
  int status = exit_status_test();
  if (status) return status;

  ktest_finish_all();
  return 0;
}
