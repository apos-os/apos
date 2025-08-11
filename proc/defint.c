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

#include "proc/defint.h"

#include "common/atomic.h"
#include "common/attributes.h"
#include "common/kassert.h"
#include "common/list.h"
#include "common/per_cpu.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

#define MAX_QUEUED_DEFINTS 100

typedef struct {
  defint_func_t f;
  void* arg;
} defint_data_t;

// Global defint state.
static kspinlock_intsafe_t g_defint_lock = KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC;
static defint_data_t g_defint_queue[MAX_QUEUED_DEFINTS] GUARDED_BY(g_defint_lock);
static int g_queue_start GUARDED_BY(g_defint_lock) = 0;
static int g_queue_len GUARDED_BY(g_defint_lock) = 0;

// Per-cpu defint state.
static DECLARE_PER_CPU(atomic32_t, g_defints_enabled) = ATOMIC32_INIT(0);
static DECLARE_PER_CPU(defint_running_t, g_defint_running) = DEFINT_NONE;

void defint_schedule(void (*f)(void*), void* arg) {
  kspin_lock_early(&g_defint_lock);
  KASSERT(g_queue_len < MAX_QUEUED_DEFINTS);
  int idx = (g_queue_start + g_queue_len) % MAX_QUEUED_DEFINTS;
  KASSERT_DBG(g_defint_queue[idx].f == NULL);
  defint_data_t* defint = &g_defint_queue[idx];
  defint->f = f;
  defint->arg = arg;
  g_queue_len++;
#if ENABLE_TSAN
  // Release all this thread's values to the defint as an explicit sync point.
  tsan_release(NULL, TSAN_DEFINTS);
#endif
  kspin_unlock_early(&g_defint_lock);
}

defint_state_t defint_state(void) {
  return atomic_load_relaxed(&PER_CPU(g_defints_enabled));
}

defint_state_t defint_set_state(defint_state_t s) {
#if ENABLE_TSAN
  if (s) {
    tsan_release(NULL, TSAN_DEFINTS);
  }
#endif
  bool old = atomic_xchg_relaxed(&PER_CPU(g_defints_enabled), s);
  if (s) {
    defint_process_queued(/* force= */ false);
#if ENABLE_TSAN
  } else {
    tsan_acquire(NULL, TSAN_DEFINTS);
#endif
  }
  return old;
}

// NO_TSAN: this manipulates the current thread execution state, which confuses
// TSAN for accesses that happen inside the function.
// TODO(aoates): figure out a way to have TSAN enabled for this function, or
// most of it.
NO_TSAN void defint_process_queued(bool force) {
  if (!interrupts_enabled() && !force) {
    return;
  }
  if (!atomic_load_relaxed(&PER_CPU(g_defints_enabled))) {
    return;
  }
  KASSERT_DBG(PER_CPU(g_defint_running) == DEFINT_NONE);

  sched_disable_preemption();

  // Prevent any new defints from being processed while we're working.
  kspinstate_t lock_state = kspin_lock_early(&g_defint_lock);
  atomic_store_relaxed(&PER_CPU(g_defints_enabled), false);
  PER_CPU(g_defint_running) =
      (atomic_load_relaxed(&kthread_current_thread()->interrupt_level) == 0)
          ? DEFINT_THREAD_CTX
          : DEFINT_INTERRUPT_CTX;

  // TODO(aoates): consider capping the number of defints we run at a given time
  // to minimize impact on the thread we're victimizing.
  while (g_queue_len > 0) {
    defint_data_t* data = &g_defint_queue[g_queue_start];

    kspin_unlock_early(&g_defint_lock);
    enable_interrupts();
    data->f(data->arg);
    kspin_lock_early(&g_defint_lock);

    data->f = NULL;
    g_queue_start = (g_queue_start + 1) % MAX_QUEUED_DEFINTS;
    g_queue_len--;
  }
  PER_CPU(g_defint_running) = DEFINT_NONE;
  atomic_store_relaxed(&PER_CPU(g_defints_enabled), true);

  // TODO(aoates): if we would have preempted the process during the defint, do
  // so now (in the scheduler).
  sched_restore_preemption();
  kspin_unlock_early2(&g_defint_lock, lock_state);
}

void _defint_disabled_die(void) {
  die("Leaving code block without reenabling defints");
}

NO_SANITIZER
defint_running_t defint_running_state(void) {
  return PER_CPU(g_defint_running);
}
