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

// Atomic types and operations.  Atomics are interrupt, defint, and SMP-safe.
// Generally follows the C11 memory model, and based on the Linux atomics API
// (https://docs.kernel.org/core-api/wrappers/atomic_t.html).
#ifndef APOO_COMMON_ATOMIC_H
#define APOO_COMMON_ATOMIC_H

#include <stdint.h>

// Memory orders.
#define ATOMIC_RELAXED __ATOMIC_RELAXED

// An unsigned 32-bit value that can only be accessed with atomic operations.
struct atomic32;
typedef struct atomic32 atomic32_t;
#define ATOMIC32_INIT(x) { x }

// Basic relaxed (non-synchronizing) atomic operations.
#define atomic_load_relaxed(x) __atomic_load_n(&(x)->_val, ATOMIC_RELAXED)
#define atomic_store_relaxed(x, val) \
  __atomic_store_n(&(x)->_val, val, ATOMIC_RELAXED)
#define atomic_add_relaxed(x, val) \
  __atomic_add_fetch(&(x)->_val, val, ATOMIC_RELAXED)
#define atomic_sub_relaxed(x, val) \
  __atomic_sub_fetch(&(x)->_val, val, ATOMIC_RELAXED)

// Internal definitions.
struct atomic32 {
  uint32_t _val;  // Must not be accessed directly.
};

#endif
