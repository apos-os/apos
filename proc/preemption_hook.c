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

#include "arch/dev/interrupts.h"
#include "common/atomic.h"
#include "common/hash.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"

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
  // TODO(SMP): replace this with a per-cpu variable.
  static atomic32_t rng = ATOMIC32_INIT(12345);

  // If interrupts are enabled, then we know we're not currently processing an
  // interrupt.
  if (kthread_current_thread() && interrupts_enabled() &&
      sched_preemption_enabled()) {
    // Racy RMW is OK.  Worst case scenario we repeat some RNG values.
    // TODO(SMP): replace with relaxed CAS.
    uint32_t rng_val = fnv_hash(atomic_load_relaxed(&rng));
    if (rng_val == 0) rng_val = get_time_ms();
    atomic_store_relaxed(&rng, rng_val);
    bool tick = (rng_val % 15) < (uint32_t)level;

    if (tick) {
#if ARCH == ARCH_riscv64
      rsv_raise_softint(RSV_SOFTINT_PREEMPT);
#else
      PUSH_AND_DISABLE_INTERRUPTS();
      sched_tick();
      POP_INTERRUPTS();
#endif
    }
  }
}
