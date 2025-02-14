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
#include "test/kernel_tests.h"

#include "common/atomic.h"
#include "test/ktest.h"

static void atomic32_test(void) {
  KTEST_BEGIN("atomic32_t: basic read/write test");
  atomic32_t x = ATOMIC32_INIT(5);
  KEXPECT_EQ(5, atomic_load_relaxed(&x));
  atomic_store_relaxed(&x, 6);
  KEXPECT_EQ(6, atomic_load_relaxed(&x));
  atomic_add_relaxed(&x, 5);
  KEXPECT_EQ(11, atomic_load_relaxed(&x));
  atomic_sub_relaxed(&x, 3);
  KEXPECT_EQ(8, atomic_load_relaxed(&x));
}

void atomic_test(void) {
  KTEST_SUITE_BEGIN("Atomics");
  atomic32_test();
}

