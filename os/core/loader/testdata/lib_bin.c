// Copyright 2026 Andrew Oates.  All Rights Reserved.
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
#include "os/core/loader/testdata/libs_header.h"

#include <stdio.h>

IMPL_FUNC(bin_, funcX, {})

static int result = 0;

#define EXPECT_EQ(_val1, _val2)                                       \
  do {                                                                \
    if ((_val1) != (_val2)) {                                         \
      printf("Failure: %s:%d: %s expected %d, actual %d\n", __FILE__, \
             __LINE__, #_val1, (_val2), (_val1));                     \
      result = 1;                                                     \
    }                                                                 \
  } while (0)

int main(void) {
  testlib_calls_t c = {};
  funcA(&c);
  funcX(&c);

  EXPECT_EQ(c.lib1_funcA, 1);
  EXPECT_EQ(c.lib2_funcB, 3);
  EXPECT_EQ(c.lib2_funcC, 1);
  EXPECT_EQ(c.lib3_funcD, 1);
  EXPECT_EQ(c.lib4_funcE, 1);
  EXPECT_EQ(c.lib4_funcA, 0);
  EXPECT_EQ(c.lib4_funcB, 0);
  EXPECT_EQ(c.bin_funcX, 2);
  EXPECT_EQ(c.lib4_funcX, 0);
  // TODO(aoates): test global data relocations in addition to function calls.
  // TODO(aoates): test SONAME overrides with this.
  if (result == 0) {
    printf("Passed!\n");
  }
  return result;
}
