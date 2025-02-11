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

#ifndef APOO_COMMON_ALIGNMENT_H
#define APOO_COMMON_ALIGNMENT_H

#include <stdalign.h>
#include <stdint.h>

#include "common/attributes.h"
#include "common/kstring.h"

// Evaluates true if the given pointer is aligned properly for the given type.
#define IS_ALIGNED(ptr, type) ((addr_t)(ptr) % alignof(type) == 0)

// Asserts that the given pointer is aligned correctly for the given type.
#define ASSERT_ALIGNED(ptr, type) KASSERT((addr_t)(ptr) % alignof(type) == 0)

// TODO(aoates): allow optimizations of this on platforms that have fast
// unaligned accesses.

static inline ALWAYS_INLINE uint64_t read_unaligned_u64(const void* ptr) {
  uint64_t value;
  kmemcpy(&value, ptr, sizeof(uint64_t));
  return value;
}

#endif
