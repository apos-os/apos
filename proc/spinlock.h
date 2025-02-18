// Copyright 2019 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_PROC_SPINLOCK_H
#define APOO_PROC_SPINLOCK_H

#include "arch/dev/interrupts.h"
#include "common/config.h"
#include "common/types.h"
#include "proc/defint.h"
#include "proc/thread_annotations.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

// TODO(aoates): define a proper spinlock when SMP is possible.

// There are two types of spinlocks:
//  - Normal: disables preemption and deferred interrupts, and must not be used
//      from an interrupt context.
//  - Interrupt-safe: also disables interrupts (and therefore can be used from
//      an interrupt context, and to protect state shared between normal code
//      and interrupts)
//
// They are implemented similarly, but given different types so that the
// typesystem can enforce correct usage.

// Internal implementation struct.
typedef struct {
  // The thread currently holding the spinlock, or -1 if free.
  kthread_id_t holder;

#if ENABLE_TSAN
  tsan_lock_data_t tsan;
#endif
} kspinlock_impl_t;

// A normal spinlock.
typedef struct CAPABILITY("spinlock") {
  kspinlock_impl_t _lock;

  // Defint state when the spinlock was locked.
  defint_state_t defint_state;
} kspinlock_t;

// An interrupt-safe spinlock.
typedef struct CAPABILITY("spinlock") {
  kspinlock_impl_t _lock;

  // Interrupt state when the spinlock was locked.
  interrupt_state_t int_state;
} kspinlock_intsafe_t;

extern const kspinlock_t KSPINLOCK_NORMAL_INIT;
extern const kspinlock_intsafe_t KSPINLOCK_INTERRUPT_SAFE_INIT;

#if ENABLE_TSAN
# define KSPINLOCK_NORMAL_INIT_STATIC {{ -1, TSAN_LOCK_DATA_INIT }, false }
# define KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC {{ -1, TSAN_LOCK_DATA_INIT }, 0 }
#else
# define KSPINLOCK_NORMAL_INIT_STATIC {{ -1 }, false }
# define KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC {{ -1 }, 0 }
#endif

// Lock the given spinlock.  In a non-SMP environment, simply disables
// preemption, defints, and optionally interrupts (depending on the type).
// Threads must not block while holding a spinlock.
void kspin_lock(kspinlock_t* l) ACQUIRE(l);
void kspin_lock_int(kspinlock_intsafe_t* l) ACQUIRE(l);

// Unlock the spinlock.
void kspin_unlock(kspinlock_t* l) RELEASE(l);
void kspin_unlock_int(kspinlock_intsafe_t* l) RELEASE(l);

// Returns true if the spinlock is held by the current thread.
// TODO(aoates): convert these to assertions.
bool kspin_is_held(const kspinlock_t* l);
bool kspin_is_held_int(const kspinlock_intsafe_t* l);

#endif
