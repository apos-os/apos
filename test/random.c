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
#include "test/random.h"

#include "common/atomic.h"
#include "common/hash.h"
#include "common/kassert.h"

uint32_t test_rand(void) {
  static atomic32_t val = ATOMIC32_INIT(12345);
  while (true) {
    uint32_t cval = atomic_load_relaxed(&val);
    uint32_t next = fnv_hash(cval);
    KASSERT(cval != 0);
    if (atomic_cmp_xchg_relaxed_weak(&val, &cval, next)) {
      return next;
    }
  }
}
