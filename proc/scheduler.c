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
#include "common/config.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/perf_trace.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread-queue.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/raw_spinlock.h"
#include "proc/signal/signal.h"
#include "memory/memory.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "proc/thread_annotations.h"
#include "sanitizers/tsan/spinlock_core.h"
#include "sanitizers/tsan/tsan.h"
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
  kthread_t me = kthread_current_thread();
  sched_disable_preemption();
  while(1) {
    kspin_lock_int(&me->spin);
    me->state = KTHREAD_YIELDING;
    kspin_unlock_int(&me->spin);

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
  kspin_lock_int(&thread->spin);
  scheduler_make_runnable_locked(thread);
  kspin_unlock_int(&thread->spin);
}

void scheduler_make_runnable_locked(kthread_t thread) {
  kspin_assert_is_held_int(&thread->spin);
  KASSERT_DBG(thread->state == KTHREAD_PENDING ||
              thread->state == KTHREAD_YIELDING);
  raw_spin_lock(&g_run_queue.spin);
  kthread_queue_push_locked(&g_run_queue, thread);
  raw_spin_unlock(&g_run_queue.spin);
}

TSAN_CORE_FN
void scheduler_interrupt_thread(kthread_t thread) {
  tsc_kspin_lock_int(&thread->spin);
  if (thread->queue && thread->queue != &g_run_queue && thread->interruptable) {
    // TODO(SMP): try to write a test that catches a thread in KTHREAD_YIELDING.
    KASSERT_DBG(thread->state == KTHREAD_PENDING ||
                thread->state == KTHREAD_YIELDING);
    kthread_queue_t* queue = thread->queue;
    raw_spin_lock(&queue->spin);
    kthread_queue_remove_locked(queue, thread);
    raw_spin_unlock(&queue->spin);
    KASSERT_DBG(thread->wait_status == SWAIT_DONE);
    thread->wait_status = SWAIT_INTERRUPTED;
    scheduler_make_runnable_locked(thread);
  }
  tsc_kspin_unlock_int(&thread->spin);
}

void scheduler_yield(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  scheduler_wait_on(&g_run_queue);
  POP_INTERRUPTS();
}

// Silly helper to deal with thread safety annotations.
static inline ALWAYS_INLINE kthread_state_t read_state(kthread_t thread) {
  kspin_assert_is_held_int(&thread->spin);
  return thread->state;
}

TSAN_CORE_FN
void scheduler_yield_no_reschedule(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  raw_spin_lock(&g_run_queue.spin);
  kthread_data_t* new_thread = scheduler_pick_next(&g_run_queue, true);
  // Note: this is racy with changes in runnable --- that is OK.  If we get a
  // non-runnable thread here, assume that there _are_ no runnable threads.
  // We could also catch a thread before it has actually yielded; in that case,
  // treat it as if it weren't runnable.  We can't handle this in
  // scheduler_pick_next(), because usually we don't care when picking a thread
  // from a queue.
  if (new_thread && read_state(new_thread) == KTHREAD_PENDING &&
      atomic_load_relaxed(&new_thread->runnable)) {
    kspin_assert_is_held_int(&new_thread->spin);
    kthread_queue_remove_locked(&g_run_queue, new_thread);
    raw_spin_unlock(&g_run_queue.spin);
    // TODO(aoates): keep this locked into kthread_switch().
    tsc_kspin_unlock_int(&new_thread->spin);
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
    raw_spin_unlock(&g_run_queue.spin);
    if (new_thread) {
      kspin_assert_is_held_int(&new_thread->spin);
      KASSERT_DBG(new_thread->state == KTHREAD_PENDING ||
                  new_thread->state == KTHREAD_YIELDING);
      tsc_kspin_unlock_int(&new_thread->spin);
    }
    new_thread = g_idle_thread;
    if (ENABLE_PROFILE_IDLE && !g_idling) {
      g_idling = true;
      g_idling_start = arch_real_timer();
    }
  }
  kthread_switch(new_thread);
  POP_INTERRUPTS();
}

static void scheduler_timeout(defint_timer_t* timer, void* arg) {
  kthread_data_t* thread = arg;
  tsc_kspin_lock_int(&thread->spin);
  if (!thread->interruptable) {
    // This means the thread was already woken up by something else and we raced
    // to cancel the timeout.  Note: this is techincally racy, as (in theory)
    // the thread could have slept again (with a new timeout) before this ran.
    // This is highly unlikely, and mostly harmless --- worst case scenario we
    // end up with a spurious thread timeout.
    // TODO(aoates): consider a generation count, or check against the timeout
    // value, to avoid this causing a spurious timeout.
    // TODO(SMP): add a test that exercises this race --- and then decide if
    // this can be refactored or removed if redundant with the below.
    tsc_kspin_unlock_int(&thread->spin);
    kthread_unref(thread);
    return;
  }
  KASSERT_DBG(thread->wait_status != SWAIT_TIMEOUT);
  thread->wait_timeout_ran = true;
  if (thread->wait_status == SWAIT_DONE && thread->queue != NULL &&
      thread->queue != &g_run_queue) {
    KASSERT_DBG(thread->state == KTHREAD_PENDING ||
                thread->state == KTHREAD_YIELDING);

    kthread_queue_t* queue = thread->queue;
    raw_spin_lock(&queue->spin);
    kthread_queue_remove_locked(queue, thread);
    raw_spin_unlock(&queue->spin);
    thread->wait_status = SWAIT_TIMEOUT;
    scheduler_make_runnable_locked(thread);
  }
  tsc_kspin_unlock_int(&thread->spin);
  kthread_unref(thread);
}

TSAN_CORE_FN
kthread_t scheduler_pick_next(kthread_queue_t* queue, bool prefer_runnable)
    NO_THREAD_SAFETY_ANALYSIS {
  while (true) {
    kthread_t candidate = NULL;
    raw_spin_assert_held(&queue->spin);
    // If queue is empty, return NULL.
    if (!queue->head) {
      return NULL;
    }

    if (prefer_runnable) {
      // Look for a runnable thread.
      kthread_data_t* thread = queue->head;
      while (thread) {
        if (atomic_load_relaxed(&thread->runnable)) {
          candidate = thread;
          break;
        }
        thread = thread->next;
      }
    }

    // If there is no runnable thread, or we don't care, take the first.
    if (!candidate) {
      candidate = queue->head;
    }

    // Found a candidate, ref it before unlocking queue.
    if (ENABLE_TSAN_NON_CORE) {
      tsan_disable();  // Don't want to synchronize on the candidate refcount.
    }
    kthread_ref(candidate);
    raw_spin_unlock(&queue->spin);

    // Lock the thread and check if it's still on the correct queue.
    tsc_kspin_lock_int(&candidate->spin);
    if (candidate->queue == queue) {
      // Success!  Unref the thread (the queue's reference is still valid),
      // re-lock the queue (in order after the thread's lock), and return it.
      kthread_unref(candidate);
      raw_spin_lock(&queue->spin);
      if (ENABLE_TSAN_NON_CORE) {
        tsan_restore();
      }
      return candidate;
    }

    // Race: thread was removed from the queue by another. Unlock and retry.
    tsc_kspin_unlock_int(&candidate->spin);
    kthread_unref(candidate);
    raw_spin_lock(&queue->spin);
    if (ENABLE_TSAN_NON_CORE) {
      tsan_restore();
    }
  }
}

kthread_t scheduler_pop(kthread_queue_t* queue, bool prefer_runnable) {
  raw_spin_lock(&queue->spin);
  kthread_t thread = scheduler_pick_next(queue, prefer_runnable);
  if (!thread) {
    raw_spin_unlock(&queue->spin);
    return NULL; // Queue was empty
  }
  kspin_assert_is_held_int(&thread->spin);

  // Thread is locked from scheduler_pick_next. Remove it from the queue.
  kthread_queue_remove_locked(queue, thread);
  raw_spin_unlock(&queue->spin);
  tsc_kspin_unlock_int(&thread->spin);

  return thread;
}

TSAN_CORE_FN
int scheduler_wait(kthread_queue_t* queue, swait_flags_t flags, long timeout_ms,
                   kmutex_t* mu, kspinlock_t* sp,
                   raw_spinlock_t* rsp) NO_THREAD_SAFETY_ANALYSIS {
  kthread_t current = kthread_current_thread();
  // We should never be blocking if we're holding a spinlock (unless it's the
  // one we're unlocking atomically as part of this call).
  KASSERT_DBG(current->spinlocks_held == (sp ? 1 : 0));

  // Make sure we don't try and preempt ourselves while we're yielding.
#if ENABLE_TSAN
  bool preemptible = (atomic_load_relaxed(&current->preemption_disables) == 0);
#endif
#if ENABLE_TSAN_NON_CORE
  tsan_disable();
#endif
  sched_disable_preemption();
  tsc_kspin_lock_int(&current->spin);
  bool interruptable = !(flags & SWAIT_NO_INTERRUPT);
  if (interruptable) {
    if (!(flags & SWAIT_NO_SIGNAL_CHECK)) {
      const ksigset_t dispatchable = proc_dispatchable_signals();
      if (!ksigisemptyset(dispatchable)) {
        current->wait_status = SWAIT_INTERRUPTED;
        tsc_kspin_unlock_int(&current->spin);
        sched_restore_preemption();
#if ENABLE_TSAN_NON_CORE
        tsan_restore();
#endif
        return SWAIT_INTERRUPTED;
      }
    }

    if (timeout_ms > 0) {
      // TODO(aoates): this ref/unref, if expensive, would be a good candidate
      // for an RCU-type approach.  It's logically possible for the defint timer
      // to outlive the thread (even when cancelled), but I suspect impossible
      // in practice --- we just need a way to say "wait until all timers have
      // run" after we cancel.
      kthread_ref(current);
      defint_timer_create(get_time_ms() + timeout_ms, &scheduler_timeout,
                          current, &current->timeout_timer);
    }
  } else {
    KASSERT_DBG(timeout_ms == -1);
  }

  current->state = KTHREAD_YIELDING;
  current->interruptable = interruptable;
  current->wait_status = SWAIT_DONE;
  current->wait_timeout_ran = false;
  raw_spin_lock(&queue->spin);
  kthread_queue_push_locked(queue, current);
  raw_spin_unlock(&queue->spin);
  tsc_kspin_unlock_int(&current->spin);
#if ENABLE_TSAN_NON_CORE
  tsan_restore();
#endif
  // Note: after this point, we could be already put back on the run queue!  We
  // won't be actually run again until we yield.
  interrupt_state_t rsp_state;
  if (rsp) {
    rsp_state = raw_spin_unlock_noint(rsp);
  }
  if (sp) {
    kspin_unlock(sp);
  }
  if (mu) {
    kmutex_unlock_no_yield(mu);
  }
#if ENABLE_TSAN
  if (!rsp && !sp && !mu && !preemptible) {
    tsan_release(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
  }
#endif
  scheduler_yield_no_reschedule();
#if ENABLE_TSAN
  if (!rsp && !sp && !mu && !preemptible) {
    tsan_acquire(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
  }
#endif
  tsc_kspin_lock_int(&current->spin);
  int result = current->wait_status;
  if (timeout_ms > 0 && !current->wait_timeout_ran) {
    current->interruptable = false;
    if (defint_timer_cancel(&current->timeout_timer)) {
      kthread_unref(current);
    }
  }
  tsc_kspin_unlock_int(&current->spin);
  if (mu) {
    kmutex_lock(mu);
  }
  if (sp) {
    kspin_lock(sp);
  }
  if (rsp) {
    raw_spin_lock_noint(rsp, rsp_state);
  }

  sched_restore_preemption();
  return result;
}

void scheduler_wait_on(kthread_queue_t* queue) {
  int result = scheduler_wait(queue, SWAIT_NO_INTERRUPT, -1, NULL, NULL, NULL);
  KASSERT_DBG(result == 0);
}

int scheduler_wait_on_interruptable(kthread_queue_t* queue, long timeout_ms) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, NULL, NULL, NULL);
}

int scheduler_wait_on_locked(kthread_queue_t* queue, long timeout_ms,
                             kmutex_t* mu) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, mu, NULL, NULL);
}

int scheduler_wait_on_plocked(kthread_queue_t* queue, long timeout_ms,
                             pmutex_t* mu) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, &mu->_mu, NULL, NULL);
}

int scheduler_wait_on_splocked(kthread_queue_t* queue, long timeout_ms,
                               kspinlock_t* sp) {
  return scheduler_wait(queue, SWAIT_DEFAULT, timeout_ms, NULL, sp, NULL);
}

void scheduler_wake_one(kthread_queue_t* queue) {
  PUSH_AND_DISABLE_INTERRUPTS();
#if ENABLE_TSAN
  tsan_release(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
#endif
  // Wake one should always prefer a runnable thread.
  kthread_t thread = scheduler_pop(queue, /* prefer_runnable= */ true);
  if (thread) {
    scheduler_make_runnable(thread);
  }
  POP_INTERRUPTS();
}

void scheduler_wake_all(kthread_queue_t* queue) {
  PUSH_AND_DISABLE_INTERRUPTS();
#if ENABLE_TSAN
  tsan_release(&g_implicit_scheduler_tsan_lock, TSAN_LOCK);
#endif
  kthread_t thread;
  // Wake all does not need to prefer runnable, just drain the queue.
  while ((thread = scheduler_pop(queue, /* prefer_runnable= */ false)) != NULL) {
    scheduler_make_runnable(thread);
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
