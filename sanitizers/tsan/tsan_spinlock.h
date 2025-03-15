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

// A basic uninstrumented spinlock for use in TSAN code.  Interrupt-safe.
#ifndef APOO_SANITIZERS_TSAN_TSAN_SPINLOCK_H
#define APOO_SANITIZERS_TSAN_TSAN_SPINLOCK_H

#include "arch/dev/interrupts.h"
#include "common/attributes.h"
#include "proc/thread_annotations.h"

// TODO(SMP): when SMP is enabled, spin as well as disable interrupts.
typedef struct CAPABILITY("tsan_spinlock") {
  int locked;
  interrupt_state_t interrupts;
} tsan_spinlock_t;

#define TSAN_SPINLOCK_INIT (tsan_spinlock_t){0, 0}

static inline ALWAYS_INLINE
void tsan_spinlock_lock(tsan_spinlock_t* sp)
    ACQUIRE(sp) NO_THREAD_SAFETY_ANALYSIS {
  sp->locked = true;
  sp->interrupts = save_and_disable_interrupts_raw();
}

static inline ALWAYS_INLINE
void tsan_spinlock_unlock(tsan_spinlock_t* sp)
    RELEASE(sp) NO_THREAD_SAFETY_ANALYSIS {
  restore_interrupts_raw(sp->interrupts);
}

#endif
