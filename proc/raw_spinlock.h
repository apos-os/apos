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

// A raw (uninstrumented) interrupt-safe spinlock.
#ifndef APOO_PROC_RAW_SPINLOCK_H
#define APOO_PROC_RAW_SPINLOCK_H

#include "common/kassert.h"
#include "dev/interrupts.h"
#include "common/atomic.h"

typedef struct CAPABILITY("spinlock") {
  // TODO(SMP): use the atomic flag.
  atomic32_t flag;
  interrupt_state_t int_state;
} raw_spinlock_t;

#define RAW_SPIN_INIT (raw_spinlock_t){ ATOMIC32_INIT(0), 0 }

// If TSAN is enabled in non-core mode, we want the atomic accesses in
// raw_spinlock_t to NOT synchronize.  This requires making them non-inline and
// fully disabling sanitizers in them.
#ifndef RAWSP_DISABLE_TSAN
// Disable TSAN only in non-core TSAN mode.
#define RAWSP_DISABLE_TSAN ENABLE_TSAN_NON_CORE
#endif

#if RAWSP_DISABLE_TSAN
#define _RAWSP_FN_ATTRS NO_INLINE NO_SANITIZER __attribute__((unused))
#else
#define _RAWSP_FN_ATTRS inline ALWAYS_INLINE
#endif

static _RAWSP_FN_ATTRS
void raw_spin_lock(raw_spinlock_t* sp)
    ACQUIRE(sp) NO_THREAD_SAFETY_ANALYSIS {
  interrupt_state_t int_state = save_and_disable_interrupts_raw();
  KASSERT(atomic_load_acquire(&sp->flag) == 0);
  atomic_store_relaxed(&sp->flag, 1);
  sp->int_state = int_state;
}

static _RAWSP_FN_ATTRS
void raw_spin_unlock(raw_spinlock_t* sp)
    RELEASE(sp) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(atomic_load_relaxed(&sp->flag) == 1);
  interrupt_state_t int_state = sp->int_state;
  atomic_store_release(&sp->flag, 0);
  restore_interrupts_raw(int_state);
}

static _RAWSP_FN_ATTRS
void raw_spin_assert_held(const raw_spinlock_t* l) ASSERT_CAPABILITY(l) {
  // TODO(SMP): assert holder is current thread.
  KASSERT(atomic_load_relaxed(&l->flag));
}

static inline ALWAYS_INLINE
void raw_spin_ctor(const raw_spinlock_t* l) ASSERT_CAPABILITY(l) {}

// Variants for use in the scheduler code which don't re-enable interrupts.
static _RAWSP_FN_ATTRS
void raw_spin_lock_noint(raw_spinlock_t* sp, interrupt_state_t int_state)
    ACQUIRE(sp) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT_DBG(!interrupts_enabled());
  KASSERT(atomic_load_acquire(&sp->flag) == 0);
  atomic_store_relaxed(&sp->flag, 1);
  sp->int_state = int_state;
}

static _RAWSP_FN_ATTRS
interrupt_state_t raw_spin_unlock_noint(raw_spinlock_t* sp)
    RELEASE(sp) NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(atomic_load_relaxed(&sp->flag) == 1);
  interrupt_state_t int_state = sp->int_state;
  atomic_store_release(&sp->flag, 0);
  return int_state;
}

#endif
