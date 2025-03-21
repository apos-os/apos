// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SANITIZERS_TSAN_TSAN_ACCESS_H
#define APOO_SANITIZERS_TSAN_TSAN_ACCESS_H

#include <stdbool.h>

#include "common/attributes.h"
#include "common/types.h"

typedef enum {
  TSAN_ACCESS_READ = 1,
  TSAN_ACCESS_WRITE = 2,
  TSAN_ACCESS_IS_ATOMIC = 4,
} tsan_access_type_t;

// Helpers that force the result to be a bool to avoid truncation issues when
// storing in bitfields.
ALWAYS_INLINE
static inline bool tsan_is_read(tsan_access_type_t t) {
  return t & TSAN_ACCESS_READ;
}

ALWAYS_INLINE
static inline bool tsan_is_write(tsan_access_type_t t) {
  return t & TSAN_ACCESS_WRITE;
}

ALWAYS_INLINE
static inline bool tsan_is_atomic(tsan_access_type_t t) {
  return t & TSAN_ACCESS_IS_ATOMIC;
}

// Call to check an access from a hook.
bool tsan_check(addr_t pc, addr_t addr, uint8_t size, tsan_access_type_t type);

// As above, but allowed to be an unaligned load that hits two shadow cells.
bool tsan_check_unaligned(addr_t pc, addr_t addr, uint8_t size,
                          tsan_access_type_t type);

// Access a range of memory.
bool tsan_check_range(addr_t pc, addr_t addr, size_t len,
                      tsan_access_type_t type);

// Mark the given region as stack or non-stack.  The region must be page-aligned
// and contain an integer number of pages.
void tsan_mark_stack(addr_t start, size_t len, bool is_stack);

#endif
