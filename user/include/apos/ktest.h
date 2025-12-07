// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_USER_INCLUDE_APOS_KTEST_H
#define APOO_USER_INCLUDE_APOS_KTEST_H

#include <stddef.h>

#define KTEST_NAME_LEN 32

// A kernel test to run.
typedef struct {
  // The name of the test case.
  char name[KTEST_NAME_LEN];
} apos_ktest_t;

// Run a set of kernel tests.
int apos_run_ktests(const apos_ktest_t* tests, size_t num);

#endif
