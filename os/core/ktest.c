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
//
// Runs APOS kernel tests.  Usage:
//  ktest <test1> <test2> ...

#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>

#include <apos/ktest.h>

int main(int argc, char* argv[]) {
  if (argc < 2) {
    const char kUsage[] = "No tests given.\nUsage: ktest <test1> <test2> ...\n";
    write(2, kUsage, strlen(kUsage));
    return 1;
  }

  const int num_tests = argc - 1;
  apos_ktest_t* tests = malloc(sizeof(apos_ktest_t) * num_tests);
  for (int i = 0; i < num_tests; ++i) {
    memset(tests[i].name, 0, KTEST_NAME_LEN);
    strncpy(tests[i].name, argv[1 + i], KTEST_NAME_LEN - 1);
  }

  apos_run_ktests(tests, num_tests);
  return 0;
}
