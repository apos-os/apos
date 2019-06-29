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

#include "common/kassert.h"
#include "proc/scheduler.h"

const kspinlock_t KSPINLOCK_INIT = {-1};

void kspin_lock(kspinlock_t* l) {
  KASSERT(l->holder == -1);
  sched_disable_preemption();
  kthread_t me = kthread_current_thread();
  l->holder = me->id;
  me->spinlocks_held++;
}

void kspin_unlock(kspinlock_t* l) {
  kthread_t me = kthread_current_thread();
  KASSERT(l->holder == me->id);
  KASSERT(me->spinlocks_held > 0);
  l->holder = -1;
  me->spinlocks_held--;
  sched_restore_preemption();
}
