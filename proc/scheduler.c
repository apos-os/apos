// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include <stdint.h>

#include "arch/dev/timer.h"
#include "arch/proc/stack_trace.h"
#include "common/atomic.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/perf_trace.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/signal/signal.h"
#include "memory/memory.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "sanitizers/tsan/tsan_lock.h"

_Static_assert(!(ENABLE_PROFILING && ENABLE_PROFILE_IDLE),
               "Cannot enable PROFILING and PROFILE_IDLE at the same time");

static kthread_t g_idle_thread = 0;
static kthread_queue_t g_run_queue;
static bool g_idling = false;
static uint64_t g_idling_start = 0;

#if ENABLE_TSAN
// An implicit TSAN lock for code that uses scheduler_wait_on() variants without
// a lock (i.e. non-preemptible code).  This is required so that
// synchronizations are propagated properly across those calls.  It would be
// better to use a per-wait-queue vector clock (to get finer-grained analysis),
// but that blows up the size of all the wait queues significantly, and we want
// to get rid of all non-lock-based synchronization anyway.  Note that
// per-wait-queue vector clocks would flag potential future logic issues, but
// not current correctness ones (as scheduler_wait_on() is a full
// synchronization point.
// TODO(tsan): remove this when all wait queue users use explicit locks.
static tsan_lock_data_t g_implicit_scheduler_tsan_lock;
#endif

static void* idle_thread_body(void* arg) {
  sched_disable_preemption();
  while(1) {
    kthread_current_thread()->state = KTHREAD_PENDING;
    scheduler_yield_no_reschedule();
  }
  return 0;
}

// TODO(aoates): add test for interrupts/idle loop.

void scheduler_init(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_queue_init(&g_run_queue);
#if ENABLE_TSAN
  tsan_lock_init(&g_implicit_scheduler_tsan_lock);
#endif

  // Make the idle thread.
  int ret = kthread_create(&g_idle_thread, &idle_thread_body, 0);
  KASSERT(ret == 0);
  POP_INTERRUPTS();
}

void scheduler_make_runnable(kthread_t thread) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT_DBG(thread->state == KTHREAD_PENDING);
  kthread_queue_push(&g_run_queue, thread);
  POP_INTERRUPTS();
}

void scheduler_interrupt_thread(kthread_t thread) {
  PUSH_AND_DISABLE_INTERRUPTS();
  if (thread->queue && thread->queue != &g_run_queue && thread->interruptable) {
    KASSERT_DBG(thread->state == KTHREAD_PENDING);
    KASSERT_DBG(kthread_current_thread()->queue == 0x0);

    kthread_queue_remove(thread);
    KASSERT_DBG(thread->wait_status == SWAIT_DONE);
    thread->wait_status = SWAIT_INTERRUPTED;
    scheduler_make_runnable(thread);
  }
  POP_INTERRUPTS();
}

void scheduler_yield(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  scheduler_wait_on(&g_run_queue);
  POP_INTERRUPTS();
}

void scheduler_yield_no_reschedule(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* new_thread = g_run_queue.head;
  // This is inefficient, but disabled threads are not expected to be used much.
  while (new_thread && !new_thread->runnable) {
    new_thread = new_thread->next;
  }
  if (new_thread) {
    kthread_queue_remove(new_thread);
    if (ENABLE_PROFILE_IDLE && g_idling) {
      g_idling = false;
      uint64_t idle_len = arch_real_timer() - g_idling_start;
      addr_t stack_trace[32];
      int len = get_stack_trace_for_thread(new_thread, stack_trace, 32);
      // Skip the kthread_switch().
      KASSERT_DBG(len > 2);
      len--;
      perftrace_log_trace(idle_len, stack_trace + 1, len);
    }
  } else {
    new_thread = g_idle_thread;
    if (ENABLE_PROFILE_IDLE && !g_idling) {
      g_idling = true;
      g_idling_start = arch_real_timer();
    }
  }
  kthread_switch(new_thread);
  POP_INTERRUPTS();
}

static void scheduler_timeout(void* arg) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* thread = arg;
  KASSERT_DBG(thread->wait_status != SWAIT_TIMEOUT);
  KASSERT_DBG(thread->interruptable);
  thread->wait_timeout_ran = true;
  if (thread->wait_status == SWAIT_DONE && thread->queue != &g_run_queue) {
    KASSERT_DBG(thread->state == KTHREAD_PENDING);
    KASSERT_DBG(kthread_current_thread()->queue == 0x0);

    kthread_queue_remove(thread);
    thread->wait_status = SWAIT_TIMEOUT;
    scheduler_make_runnable(thread);
  }
  POP_INTERRUPTS();
}

int scheduler_wait(kthread_queue_t* queue, swait_flags_t flags, long timeout_ms,
                   kmutex_t* mu, kspinlock_t* sp) NO_THREAD_SAFETY_ANALYSIS {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_t current = kthread_current_thread();
  // We should never be blocking if we're holding a spinlock (unless it's the
  // one we're unlocking atomically as part of this call).
  KASSERT_DBG(current->spinlocks_held == (sp ? 1 : 0));

  timer_handle_t timeout_handle;
  bool interruptable = !(flags & SWAIT_NO_INTERRUPT);
  if (interruptable) {
    if (!(flags & SWAIT_NO_SIGNAL_CHECK)) {
      const ksigset_t dispatchable = proc_dispatchable_signals();
      if (!ksigisemptyset(dispatchable)) {
        current->wait_status = SWAIT_INTERRUPTED;
        POP_INTERRUPTS();
        return SWAIT_INTERRUPTED;
      }
    }

    if (timeout_ms > 0) {
      int result =
          register_event_timer(get_time_ms() + timeout_ms, &scheduler_timeout,
                               current, &timeout_handle);
      KASSERT_DBG(result == 0);
    }
  } else {
    KASSERT_DBG(timeout_ms == -1);
  }

  current->state = KTHREAD_PENDING;
  current->interruptable = interruptable;
  current->wait_status = SWAIT_DONE;
  current->wait_timeout_ran = false;
  kthread_queue_push(queue, current);
  if (sp) {
    kspin_unlock(sp);
  }
  if (mu) {
    kmutex_unlock_no_yield(mu);
  }
#if ENABLE_TSAN
  if (!sp && !mu && atomic_load_relaxed(&current->preemption_disables) > 0) {
    tsan_release(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
  }
#endif
  scheduler_yield_no_reschedule();
#if ENABLE_TSAN
  if (!sp && !mu && atomic_load_relaxed(&current->preemption_disables) > 0) {
    tsan_acquire(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
  }
#endif
  int result = current->wait_status;
  if (timeout_ms > 0 && !current->wait_timeout_ran)
    cancel_event_timer(timeout_handle);
  if (mu) {
    kmutex_lock(mu);
  }
  if (sp) {
    kspin_lock(sp);
  }
  POP_INTERRUPTS();

  return result;
}

void scheduler_wait_on(kthread_queue_t* queue) {
  int result = scheduler_wait(queue, SWAIT_NO_INTERRUPT, -1, NULL, NULL);
  KASSERT_DBG(result == 0);
}

int scheduler_wait_on_interruptable(kthread_queue_t* queue, long timeout_ms) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, NULL, NULL);
}

int scheduler_wait_on_locked(kthread_queue_t* queue, long timeout_ms,
                             kmutex_t* mu) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, mu, NULL);
}

int scheduler_wait_on_plocked(kthread_queue_t* queue, long timeout_ms,
                             pmutex_t* mu) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, &mu->_mu, NULL);
}

int scheduler_wait_on_splocked(kthread_queue_t* queue, long timeout_ms,
                               kspinlock_t* sp) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, NULL, sp);
}

void scheduler_wake_one(kthread_queue_t* queue) {
  PUSH_AND_DISABLE_INTERRUPTS();
#if ENABLE_TSAN
  tsan_release(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
#endif
  if (!kthread_queue_empty(queue)) {
    scheduler_make_runnable(kthread_queue_pop(queue));
  }
  POP_INTERRUPTS();
}

void scheduler_wake_all(kthread_queue_t* queue) {
  PUSH_AND_DISABLE_INTERRUPTS();
#if ENABLE_TSAN
  tsan_release(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
#endif
  while (!kthread_queue_empty(queue)) {
    scheduler_make_runnable(kthread_queue_pop(queue));
  }
  POP_INTERRUPTS();
}

void sched_disable_preemption(void) {
  atomic_add_relaxed(&kthread_current_thread()->preemption_disables, 1);
}

void sched_restore_preemption(void) {
  uint32_t val =
      atomic_sub_relaxed(&kthread_current_thread()->preemption_disables, 1);
  KASSERT((int)val >= 0);
}

void sched_enable_preemption_for_test(void) {
  kthread_t me = kthread_current_thread();
  KASSERT(atomic_load_relaxed(&me->preemption_disables) == 1);
  atomic_store_relaxed(&me->preemption_disables, 0);
}

bool sched_preemption_enabled(void) {
  kthread_t me = kthread_current_thread();
  return atomic_load_relaxed(&me->preemption_disables) == 0;
}

void sched_tick(void) {
  // TODO(aoates): move g_run_queue short-circuit into scheduler_yield() after
  // verifying it won't break any tests.
  kthread_t me = kthread_current_thread();
  if (atomic_load_relaxed(&me->preemption_disables) == 0 &&
      !kthread_queue_empty(&g_run_queue)) {
    scheduler_yield();
  }
}

#if ENABLE_TSAN
void scheduler_tsan_acquire(void) {
  tsan_acquire(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
}
#endif
