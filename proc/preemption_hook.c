// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "proc/preemption_hook.h"

#include "common/hash.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"

_Static_assert(PREEMPTION_INDUCE_LEVEL_LIST >= 0 &&
                   PREEMPTION_INDUCE_LEVEL_LIST <= 10,
               "PREEMPTION_INDUCE_LEVEL_LIST out of range");

_Static_assert(PREEMPTION_INDUCE_LEVEL_HTBL >= 0 &&
                   PREEMPTION_INDUCE_LEVEL_HTBL <= 10,
               "PREEMPTION_INDUCE_LEVEL_HTBL out of range");

_Static_assert(PREEMPTION_INDUCE_LEVEL_CIRCBUF >= 0 &&
                   PREEMPTION_INDUCE_LEVEL_CIRCBUF <= 10,
               "PREEMPTION_INDUCE_LEVEL_CIRCBUF out of range");

void sched_preempt_me(int level) {
  static uint32_t rng = 12345;
  static kspinlock_t rng_lock = KSPINLOCK_NORMAL_INIT_STATIC;

  // If interrupts are enabled, then we know we're not currently processing an
  // interrupt.
  if (kthread_current_thread() && interrupts_enabled() &&
      kthread_current_thread()->preemption_disables == 0) {
    kspin_lock(&rng_lock);
    rng = fnv_hash(rng);
    if (rng == 0) rng = get_time_ms();
    bool tick = (rng % 15) < (uint32_t)level;
    kspin_unlock(&rng_lock);

    if (tick) {
      sched_tick();
    }
  }
}
