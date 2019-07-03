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
#include "proc/scheduler.h"

const kspinlock_t KSPINLOCK_NORMAL_INIT = {SPINLOCK_NORMAL, -1, false, 0};
const kspinlock_t KSPINLOCK_INTERRUPT_SAFE_INIT = {SPINLOCK_INTERRUPT_SAFE, -1,
                                                   false, 0};

void kspin_lock(kspinlock_t* l) {
  interrupt_state_t int_state = 0;
  // TODO(aoates): write a test that that catches the scenario where we modify
  // the lock before we actually hold it (preemption and defints are disabled).
  bool defint_state = defint_set_state(false);
  sched_disable_preemption();
  if (l->type == SPINLOCK_INTERRUPT_SAFE) {
    // TODO(aoates): there are definitely some optimizations we can do here; for
    // example, preemption does not need to be disabled if interrupts are
    // disabled, etc (defints still need to be in case some leaf code calls
    // defint_set_state() while the spinlock is held).
    int_state = save_and_disable_interrupts();
  }
  // TODO(aoates): assert that normal spinlocks are never taken from an
  // interrupt context.
  KASSERT(l->holder == -1);
  l->defint_state = defint_state;
  l->int_state = int_state;
  kthread_t me = kthread_current_thread();
  l->holder = me->id;
  me->spinlocks_held++;
}

void kspin_unlock(kspinlock_t* l) {
  kthread_t me = kthread_current_thread();
  KASSERT(l->holder == me->id);
  KASSERT(me->spinlocks_held > 0);
  bool defint_state = l->defint_state;
  interrupt_state_t int_state = l->int_state;
  l->holder = -1;
  me->spinlocks_held--;
  if (l->type == SPINLOCK_INTERRUPT_SAFE) {
    KASSERT_DBG(interrupts_enabled() == false);
    restore_interrupts(int_state);
  }
  sched_restore_preemption();
  bool defint_prev_state = defint_set_state(defint_state);
  KASSERT(defint_prev_state == false);
}

bool kspin_is_held(const kspinlock_t* l) {
  return (l->holder == kthread_current_thread()->id);
}
