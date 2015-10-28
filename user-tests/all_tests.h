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
#ifndef APOO_USER_TESTS_ALL_TESTS_H
#define APOO_USER_TESTS_ALL_TESTS_H

#include <stdbool.h>

extern bool run_slow_tests;

void syscall_errno_test(void);
int exit_status_test(void);
void basic_signal_test(void);
void execve_test(void);
void stop_test(void);
void wait_test(void);
void fs_test(void);
void misc_syscall_test(void);

// Helper when self-exec'ing in execve() tests.
int execve_helper(int argc, char** argv);

#endif
