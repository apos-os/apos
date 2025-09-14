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

#include "proc/spinlock.h"

#include "common/attributes.h"
#include "common/kassert.h"
#include "dev/interrupts.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

const kspinlock_t KSPINLOCK_NORMAL_INIT = KSPINLOCK_NORMAL_INIT_STATIC;
const kspinlock_intsafe_t KSPINLOCK_INTERRUPT_SAFE_INIT =
    KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC;

// NO_TSAN: these are all underlying synchronization constructs that trigger
// false positives when instrumented with TSAN (for example, races on
// l->_lock.state).  When (re)implemented for SMP, these should in theory be
// instrumentable as they will use atomics that TSAN can understand --- it
// still won't make sense to instrument them, though, as it would induce
// redundant (expensive) synchronization tracking on both the lock itself and
// the implementing atomics.
// TODO(SMP): when these use atomics, update this comment, and consider having a
// mode where they _are_ instrumented for TSAN to validate the underlying
// synchronization implementation.

NO_TSAN static void kspin_lock_internal(kspinlock_impl_t* l, bool tsan) {
  KASSERT(l->holder == -1);
  kthread_t me = kthread_current_thread();
  l->holder = me->id;
  PUSH_AND_DISABLE_INTERRUPTS_NO_SYNC();
  me->spinlocks_held++;
  POP_INTERRUPTS_NO_SYNC();

#if ENABLE_TSAN
  if (tsan) {
    tsan_acquire(&l->tsan, TSAN_LOCK);
  }
#endif
}

NO_TSAN static void kspin_unlock_internal(kspinlock_impl_t* l, kthread_t me,
                                          bool tsan) {
  l->holder = -1;
  KASSERT(me->spinlocks_held > 0);
  me->spinlocks_held--;

#if ENABLE_TSAN
  if (tsan) {
    tsan_release(&l->tsan, TSAN_LOCK);
  }
#endif
}

NO_TSAN kspinstate_t kspin_lock(kspinlock_t* l) NO_THREAD_SAFETY_ANALYSIS {
  // TODO(aoates): write a test that that catches the scenario where we modify
  // the lock before we actually hold it (preemption and defints are disabled).
  bool defint_state = defint_set_state(false);
  sched_disable_preemption();
  // TODO(aoates): assert that normal spinlocks are never taken from an
  // interrupt context.
  l->_lock.state = defint_state;
  kspin_lock_internal(&l->_lock, true);
  return defint_state;
}

NO_TSAN kspinstate_t kspin_lock_int(kspinlock_intsafe_t* l) NO_THREAD_SAFETY_ANALYSIS {
  // Disabling interrupts disables preemption and defints implicitly.  Later
  // code _could_ change the defint state on its own (which would be
  // ill-advised), but it won't matter since interrupts are disabled.
  interrupt_state_t int_state = save_and_disable_interrupts(false);
  l->_lock.state = int_state;
  kspin_lock_internal(&l->_lock, true);
  return int_state;
}

#if ENABLE_TSAN
NO_TSAN kspinstate_t kspin_lock_int_no_tsan(kspinlock_intsafe_t* l) NO_THREAD_SAFETY_ANALYSIS {
  // Disabling interrupts disables preemption and defints implicitly.  Later
  // code _could_ change the defint state on its own (which would be
  // ill-advised), but it won't matter since interrupts are disabled.
  interrupt_state_t int_state = save_and_disable_interrupts_raw();
  l->_lock.state = int_state;
  kspin_lock_internal(&l->_lock, false);
  return int_state;
}
#endif

NO_TSAN void kspin_unlock(kspinlock_t* l) NO_THREAD_SAFETY_ANALYSIS {
  kthread_t me = kthread_current_thread();
  KASSERT(l->_lock.holder == me->id);
  bool defint_state = l->_lock.state;
  kspin_unlock_internal(&l->_lock, me, true);
  sched_restore_preemption();
  bool defint_prev_state = defint_set_state(defint_state);
  KASSERT(defint_prev_state == false);
}

NO_TSAN void kspin_unlock_int(kspinlock_intsafe_t* l)
    NO_THREAD_SAFETY_ANALYSIS {
  kthread_t me = kthread_current_thread();
  KASSERT(l->_lock.holder == me->id);
  interrupt_state_t int_state = l->_lock.state;
  kspin_unlock_internal(&l->_lock, me, true);
  KASSERT_DBG(interrupts_enabled() == false);
  restore_interrupts(int_state, false);
}

NO_TSAN void kspin_unlock2(kspinlock_t* l, kspinstate_t state)
    NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(l->_lock.holder != -1);
  kthread_t me = kthread_current_thread();
  kspin_unlock_internal(&l->_lock, me, true);
  sched_restore_preemption();
  bool defint_prev_state = defint_set_state(state);
  KASSERT(defint_prev_state == false);
}

NO_TSAN void kspin_unlock_int2(kspinlock_intsafe_t* l, kspinstate_t state)
    NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(l->_lock.holder != -1);
  kthread_t me = kthread_current_thread();
  kspin_unlock_internal(&l->_lock, me, true);
  KASSERT_DBG(interrupts_enabled() == false);
  restore_interrupts(state, false);
}

// TODO(tsan): use a template or preprocessor to generate these so that they
// aren't all just copy-pasted from the originals.
#if ENABLE_TSAN
NO_TSAN void kspin_unlock_int_no_tsan(kspinlock_intsafe_t* l)
    NO_THREAD_SAFETY_ANALYSIS {
  kthread_t me = kthread_current_thread();
  KASSERT(l->_lock.holder == me->id);
  interrupt_state_t int_state = l->_lock.state;
  kspin_unlock_internal(&l->_lock, me, false);
  KASSERT_DBG(interrupts_enabled() == false);
  restore_interrupts_raw(int_state);
}

NO_TSAN void kspin_unlock_int2_no_tsan(kspinlock_intsafe_t* l, kspinstate_t state)
    NO_THREAD_SAFETY_ANALYSIS {
  KASSERT(l->_lock.holder != -1);
  kthread_t me = kthread_current_thread();
  kspin_unlock_internal(&l->_lock, me, false);
  KASSERT_DBG(interrupts_enabled() == false);
  restore_interrupts_raw(state);
}

NO_TSAN kspinstate_t kspin_lock_early_no_tsan(kspinlock_intsafe_t* l)
    NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    return kspin_lock_int_no_tsan(l);
  } else {
    l->_lock.state = save_and_disable_interrupts_raw();
    return l->_lock.state;
  }
}

NO_TSAN void kspin_unlock_early_no_tsan(kspinlock_intsafe_t* l)
    NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    kspin_unlock_int_no_tsan(l);
  } else {
    restore_interrupts_raw(l->_lock.state);
  }
}

NO_TSAN void kspin_unlock_early2_no_tsan(kspinlock_intsafe_t* l, kspinstate_t state)
  NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    kspin_unlock_int2_no_tsan(l, state);
  } else {
    restore_interrupts_raw(state);
  }
}

#endif

NO_TSAN kspinstate_t kspin_lock_early(kspinlock_intsafe_t* l)
    NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    return kspin_lock_int(l);
  } else {
    l->_lock.state = save_and_disable_interrupts(false);
    return l->_lock.state;
  }
}

NO_TSAN void kspin_unlock_early(kspinlock_intsafe_t* l)
    NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    kspin_unlock_int(l);
  } else {
    restore_interrupts(l->_lock.state, false);
  }
}

NO_TSAN void kspin_unlock_early2(kspinlock_intsafe_t* l, kspinstate_t state)
  NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    kspin_unlock_int2(l, state);
  } else {
    restore_interrupts(state, false);
  }
}

NO_TSAN bool kspin_is_held(const kspinlock_t* l) {
  return (l->_lock.holder == kthread_current_thread()->id);
}

NO_TSAN bool kspin_is_held_int(const kspinlock_intsafe_t* l) {
  return (l->_lock.holder == kthread_current_thread()->id);
}

void kspin_assert_is_held(const kspinlock_t* l) {
  KASSERT(kspin_is_held(l));
}

void kspin_assert_is_held_int(const kspinlock_intsafe_t* l) {
  KASSERT(kspin_is_held_int(l));
}
