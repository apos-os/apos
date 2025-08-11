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
#include "common/attributes.h"
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
  // Defint or interrupt state from when the spinlock was locked, depending on
  // the type.
  int state;

#if ENABLE_TSAN
  tsan_lock_data_t tsan;
#endif
} kspinlock_impl_t;

// A normal spinlock.
typedef struct CAPABILITY("spinlock") {
  kspinlock_impl_t _lock;
} kspinlock_t;

// An interrupt-safe spinlock.
typedef struct CAPABILITY("spinlock") {
  kspinlock_impl_t _lock;
} kspinlock_intsafe_t;

extern const kspinlock_t KSPINLOCK_NORMAL_INIT;
extern const kspinlock_intsafe_t KSPINLOCK_INTERRUPT_SAFE_INIT;

#if ENABLE_TSAN
# define KSPINLOCK_NORMAL_INIT_STATIC {{ -1, 0, TSAN_LOCK_DATA_INIT }}
# define KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC {{ -1, 0, TSAN_LOCK_DATA_INIT }}
#else
# define KSPINLOCK_NORMAL_INIT_STATIC {{ -1, 0 }}
# define KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC {{ -1, 0 }}
#endif

typedef uint32_t kspinstate_t;

// Lock the given spinlock.  In a non-SMP environment, simply disables
// preemption, defints, and optionally interrupts (depending on the type).
// Threads must not block while holding a spinlock.
kspinstate_t kspin_lock(kspinlock_t* l) ACQUIRE(l);
kspinstate_t kspin_lock_int(kspinlock_intsafe_t* l) ACQUIRE(l);

// Unlock the spinlock.
void kspin_unlock(kspinlock_t* l) RELEASE(l);
void kspin_unlock_int(kspinlock_intsafe_t* l) RELEASE(l);

// Variants that allow out-of-order unlocking and other special use cases.  To
// unlock out of order, the return value of kspin_lock() must be stored and
// passed to kspin_unlock2() IN REVERSE LOCK ORDER.  This ensures the correct
// interrupt/defint state is restored, following lexical ordering of the locking
// rather than of the unlocking.
//
// Pass 0 for |state| to avoid restoring interrupt/defint state.  This should
// only be done when the caller manages interrupt state externally.
void kspin_unlock2(kspinlock_t* l, kspinstate_t state) RELEASE(l);
void kspin_unlock_int2(kspinlock_intsafe_t* l, kspinstate_t state) RELEASE(l);

// A variant that is safe to use early in the boot process.  Before threads/proc
// are set up, will simply disable/restore interrupts.
kspinstate_t kspin_lock_early(kspinlock_intsafe_t* l) ACQUIRE(l);
void kspin_unlock_early(kspinlock_intsafe_t* l) RELEASE(l);
void kspin_unlock_early2(kspinlock_intsafe_t* l, kspinstate_t state) RELEASE(l);

// Returns true if the spinlock is held by the current thread.
// TODO(aoates): convert these to assertions.
bool kspin_is_held(const kspinlock_t* l);
bool kspin_is_held_int(const kspinlock_intsafe_t* l);
void kspin_assert_is_held(const kspinlock_t* l) ASSERT_CAPABILITY(l);
void kspin_assert_is_held_int(const kspinlock_intsafe_t* l) ASSERT_CAPABILITY(l);

// Claim the given spinlock is locked for the purposes of construction or
// destruction of the protected data (and spinlock).  Behaves the same as
// kspin_assert_is_held() except doesn't actually take the lock or assert.
static inline ALWAYS_INLINE
void kspin_constructor(const kspinlock_t* l) ASSERT_CAPABILITY(l) {}
static inline ALWAYS_INLINE
void kspin_destructor(const kspinlock_t* l) ASSERT_CAPABILITY(l) {}
static inline ALWAYS_INLINE
void kspin_int_constructor(const kspinlock_intsafe_t* l) ASSERT_CAPABILITY(l) {}
static inline ALWAYS_INLINE
void kspin_int_destructor(const kspinlock_intsafe_t* l) ASSERT_CAPABILITY(l) {}

#endif
