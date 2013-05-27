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

#include <stdint.h>

#include "common/hash.h"
#include "test/ktest.h"

static void basic_fnv_test(void) {
  KTEST_BEGIN("fnv_hash(): basic test");
  KEXPECT_EQ(1268118805, fnv_hash(0));
  KEXPECT_EQ(4218009092, fnv_hash(1));
  KEXPECT_EQ(3958272823, fnv_hash(2));
  KEXPECT_EQ(794109580, fnv_hash(12345678));
}

static void fnv_array_test(void) {
  KTEST_BEGIN("fnv_hash_array(): basic test");

  for (uint32_t i = 0; i < 10; ++i) {
    KEXPECT_EQ(fnv_hash(i), fnv_hash_array(&i, sizeof(uint32_t)));
  }
}

static void fnv_concat_test(void) {
  KTEST_BEGIN("fnv_hash_concat(): basic test");

  KEXPECT_NE(fnv_hash_concat(1, 2), 1);
  KEXPECT_NE(fnv_hash_concat(1, 2), fnv_hash(1));
  KEXPECT_NE(fnv_hash_concat(1, 2), 2);
  KEXPECT_NE(fnv_hash_concat(1, 2), fnv_hash(2));
  KEXPECT_NE(fnv_hash_concat(1, 2), fnv_hash_concat(2, 1));

  uint32_t x = 0;
  for (int i = 0; i < 10; ++i) {
    uint32_t old_x = x;
    x = fnv_hash_concat(x, i);
    KEXPECT_NE(0, x);
    KEXPECT_NE(old_x, x);
  }
}

void hash_test(void) {
  KTEST_SUITE_BEGIN("hash test");

  basic_fnv_test();
  fnv_array_test();
  fnv_concat_test();
}
