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

#include "dev/interrupts.h"
#include "common/atomic.h"

typedef struct CAPABILITY("spinlock") {
  // TODO(SMP): use the atomic flag.
  atomic32_t flag;
  interrupt_state_t int_state;
} raw_spinlock_t;

static inline NO_TSAN ALWAYS_INLINE
void raw_spin_lock(raw_spinlock_t* sp)
    ACQUIRE(sp) NO_THREAD_SAFETY_ANALYSIS {
  sp->int_state = save_and_disable_interrupts_raw();
}

static inline NO_TSAN ALWAYS_INLINE
void raw_spin_unlock(raw_spinlock_t* sp)
    RELEASE(sp) NO_THREAD_SAFETY_ANALYSIS {
  restore_interrupts_raw(sp->int_state);
}

#endif
