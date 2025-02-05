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

#include "dev/interrupts.h"
#include "common/kassert.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

const kspinlock_t KSPINLOCK_NORMAL_INIT = KSPINLOCK_NORMAL_INIT_STATIC;
const kspinlock_intsafe_t KSPINLOCK_INTERRUPT_SAFE_INIT =
    KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC;

static void kspin_lock_internal(kspinlock_impl_t* l) {
  KASSERT(l->holder == -1);
  kthread_t me = kthread_current_thread();
  l->holder = me->id;
  me->spinlocks_held++;

#if ENABLE_TSAN
  tsan_acquire(&l->tsan, TSAN_LOCK);
#endif
}

static void kspin_unlock_internal(kspinlock_impl_t* l) {
  kthread_t me = kthread_current_thread();
  KASSERT(l->holder == me->id);
  KASSERT(me->spinlocks_held > 0);
  l->holder = -1;
  me->spinlocks_held--;

#if ENABLE_TSAN
  tsan_release(&l->tsan, TSAN_LOCK);
#endif
}

void kspin_lock(kspinlock_t* l) {
  // TODO(aoates): write a test that that catches the scenario where we modify
  // the lock before we actually hold it (preemption and defints are disabled).
  bool defint_state = defint_set_state(false);
  sched_disable_preemption();
  // TODO(aoates): assert that normal spinlocks are never taken from an
  // interrupt context.
  l->defint_state = defint_state;
  kspin_lock_internal(&l->_lock);
}

void kspin_lock_int(kspinlock_intsafe_t* l) {
  // Disabling interrupts disables preemption and defints implicitly.  Later
  // code _could_ change the defint state on its own (which would be
  // ill-advised), but it won't matter since interrupts are disabled.
  interrupt_state_t int_state = save_and_disable_interrupts();
  l->int_state = int_state;
  kspin_lock_internal(&l->_lock);
}

void kspin_unlock(kspinlock_t* l) {
  bool defint_state = l->defint_state;
  kspin_unlock_internal(&l->_lock);
  sched_restore_preemption();
  bool defint_prev_state = defint_set_state(defint_state);
  KASSERT(defint_prev_state == false);
}

void kspin_unlock_int(kspinlock_intsafe_t* l) {
  interrupt_state_t int_state = l->int_state;
  kspin_unlock_internal(&l->_lock);
  KASSERT_DBG(interrupts_enabled() == false);
  restore_interrupts(int_state);
}

bool kspin_is_held(const kspinlock_t* l) {
  return (l->_lock.holder == kthread_current_thread()->id);
}

bool kspin_is_held_int(const kspinlock_intsafe_t* l) {
  return (l->_lock.holder == kthread_current_thread()->id);
}
