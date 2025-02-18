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

#include <stdbool.h>
#include <stdint.h>

#include "common/attributes.h"

// Memory orders.
#define ATOMIC_RELAXED __ATOMIC_RELAXED
#define ATOMIC_ACQUIRE __ATOMIC_ACQUIRE
#define ATOMIC_RELEASE __ATOMIC_RELEASE
#define ATOMIC_ACQ_REL __ATOMIC_ACQ_REL
#define ATOMIC_SEQ_CST __ATOMIC_SEQ_CST

// An unsigned 32-bit value that can only be accessed with atomic operations.
struct atomic32;
typedef struct atomic32 atomic32_t;
#define ATOMIC32_INIT(x) { x, 0 }

// Basic relaxed (non-synchronizing) atomic operations.
#define atomic_load_relaxed(x) __atomic_load_n(&(x)->_val, ATOMIC_RELAXED)
#define atomic_store_relaxed(x, val) \
  __atomic_store_n(&(x)->_val, val, ATOMIC_RELAXED)
#define atomic_add_relaxed(x, val) \
  __atomic_add_fetch(&(x)->_val, val, ATOMIC_RELAXED)
#define atomic_sub_relaxed(x, val) \
  __atomic_sub_fetch(&(x)->_val, val, ATOMIC_RELAXED)

// Acquire/release atomic operations.
#define atomic_load_acquire(x) \
    __atomic_load_n(&(x)->_val, ATOMIC_ACQUIRE)
#define atomic_store_release(x, val) \
  __atomic_store_n(&(x)->_val, val, ATOMIC_RELEASE)
#define atomic_add_acq_rel(x, val) \
  __atomic_add_fetch(&(x)->_val, val, ATOMIC_ACQ_REL)
#define atomic_sub_acq_rel(x, val) \
  __atomic_sub_fetch(&(x)->_val, val, ATOMIC_ACQ_REL)

// Sequential consistency atomic operations
#define atomic_load_seq_cst(x) \
    __atomic_load_n(&(x)->_val, ATOMIC_SEQ_CST)
#define atomic_store_seq_cst(x, val) \
  __atomic_store_n(&(x)->_val, val, ATOMIC_SEQ_CST)

// An atomic flag that can be set and cleared.  Always has acquire/release
// semantics.
typedef struct {
  uint32_t _flag;
  uint32_t _padding;
} __attribute__((aligned(8))) atomic_flag_t;
#define ATOMIC_FLAG_INIT { false, 0 }

// Flag operations.
static inline ALWAYS_INLINE bool atomic_flag_get(const atomic_flag_t* f) {
  return __atomic_load_n(&f->_flag, ATOMIC_ACQUIRE);
}

static inline ALWAYS_INLINE void atomic_flag_set(atomic_flag_t* f) {
  __atomic_store_n(&f->_flag, 1, ATOMIC_RELEASE);
}

static inline ALWAYS_INLINE void atomic_flag_clear(atomic_flag_t* f) {
  __atomic_store_n(&f->_flag, 0, ATOMIC_RELEASE);
}

// Internal definitions.
// We align and size atomic32_t to ensure it always gets its own TSAN memory
// cell to avoid false shared synchronization with any nearby data hiding data
// races.
struct atomic32 {
  uint32_t _val;  // Must not be accessed directly.
  uint32_t _padding;
} __attribute__((aligned(8)));

#endif
