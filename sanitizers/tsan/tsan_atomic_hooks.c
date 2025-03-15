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
#include "sanitizers/tsan/tsan_hooks.h"

#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/tsan_access.h"
#include "sanitizers/tsan/tsan_spinlock.h"
#include "sanitizers/tsan/tsan_sync.h"

ALWAYS_INLINE
static inline bool tsan_is_acquire(__tsan_mo mo) {
  return mo == ATOMIC_ACQUIRE || mo == ATOMIC_ACQ_REL || mo == ATOMIC_SEQ_CST;
}

ALWAYS_INLINE
static inline bool tsan_is_release(__tsan_mo mo) {
  return mo == ATOMIC_RELEASE || mo == ATOMIC_ACQ_REL || mo == ATOMIC_SEQ_CST;
}

__tsan_atomic32 __tsan_atomic32_load(const volatile __tsan_atomic32* a,
                                     __tsan_mo mo) {
  // Structure of this (with first check fast-path and double read) copied from
  // clang.  I assume they had their reasons :)

  // Relaxed fast-path.
  if (!tsan_is_acquire(mo) || !tsan_initialized()) {
    tsan_check(CALLERPC, (addr_t)a, sizeof(__tsan_atomic32),
               TSAN_ACCESS_READ | TSAN_ACCESS_IS_ATOMIC);
    return __atomic_load_n(a, mo);
  }

  __tsan_atomic32 result = __atomic_load_n(a, mo);
  tsan_sync_t* sync = tsan_sync_get((addr_t)a, sizeof(__tsan_atomic32), false);
  if (sync) {
    tsan_spinlock_lock(&sync->spin);
    tsan_acquire(&sync->lock, TSAN_LOCK);
    // Re-read with the lock held so the acquire+load are an atomic pair.
    result = __atomic_load_n(a, mo);
    tsan_spinlock_unlock(&sync->spin);
  }
  tsan_check(CALLERPC, (addr_t)a, sizeof(__tsan_atomic32),
             TSAN_ACCESS_READ | TSAN_ACCESS_IS_ATOMIC);
  return result;
}

void __tsan_atomic32_store(volatile __tsan_atomic32* a, __tsan_atomic32 val,
                           __tsan_mo mo) {
  tsan_check(CALLERPC, (addr_t)a, sizeof(__tsan_atomic32),
             TSAN_ACCESS_WRITE | TSAN_ACCESS_IS_ATOMIC);

  // Relaxed fast-path.
  if (!tsan_is_release(mo) || !tsan_initialized()) {
    __atomic_store_n(a, val, mo);
    return;
  }

  tsan_sync_t* sync = tsan_sync_get((addr_t)a, sizeof(__tsan_atomic32), true);
  tsan_spinlock_lock(&sync->spin);
  tsan_release(&sync->lock, TSAN_LOCK);
  __atomic_store_n(a, val, mo);
  tsan_spinlock_unlock(&sync->spin);
}

#define DEFINE_ATOMIC_RMW(_T, _OP)                                  \
  _T _T##_OP(volatile _T* a, _T val, __tsan_mo mo) {                \
    tsan_check(CALLERPC, (addr_t)a, sizeof(_T),                     \
               TSAN_ACCESS_WRITE | TSAN_ACCESS_IS_ATOMIC);          \
                                                                    \
    /* Relaxed fast-path. */                                        \
    if (mo == ATOMIC_RELAXED || !tsan_initialized()) {              \
      return __atomic##_OP(a, val, mo);                             \
    }                                                               \
                                                                    \
    tsan_sync_t* sync = tsan_sync_get((addr_t)a, sizeof(_T), true); \
    tsan_spinlock_lock(&sync->spin);                                \
    if (tsan_is_acquire(mo)) {                                      \
      tsan_acquire(&sync->lock, TSAN_LOCK);                         \
    }                                                               \
    if (tsan_is_release(mo)) {                                      \
      tsan_release(&sync->lock, TSAN_LOCK);                         \
    }                                                               \
    _T result = __atomic##_OP(a, val, mo);                          \
    tsan_spinlock_unlock(&sync->spin);                              \
                                                                    \
    return result;                                                  \
  }

DEFINE_ATOMIC_RMW(__tsan_atomic32, _fetch_add)
DEFINE_ATOMIC_RMW(__tsan_atomic32, _fetch_sub)
DEFINE_ATOMIC_RMW(__tsan_atomic32, _fetch_or)
