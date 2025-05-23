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

// The kernel threads scheduler.
//
// This is the other half of the kthreads package --- see the description in
// kthreads.h.
//
// TODO(aoates): I'm still not wild about this interface (in particular the
// funkiness around the current thread, and waiting on queues).  Fix the
// interface once the various use cases have become clearer.
#ifndef APOO_SCHEDULER_H
#define APOO_SCHEDULER_H

#include "proc/kmutex.h"
#include "proc/kthread.h"
#include "proc/kthread-queue.h"
#include "proc/pmutex.h"
#include "proc/spinlock.h"

// Initialize the scheduler.
void scheduler_init(void);

// Add the given thread to the run queue.
void scheduler_make_runnable(kthread_t thread);

// Force the given thread to wake up (and be runnable) if its currently blocked
// on a kthread_queue_t.  If the thread isn't blocking (is on the run queue), or
// is non-interruptable, this is a no-op.
void scheduler_interrupt_thread(kthread_t thread);

// Yield to another thread on the run queue.  The current thread is
// automatically re-added to the back of the run queue.
//
// Equivalent (logically) to scheduler_wait_on(RUN_QUEUE).
void scheduler_yield(void);

// Flags to pass to scheduler_wait().  Default flags is zero.
typedef enum {
  SWAIT_DEFAULT = 0,
  SWAIT_NO_INTERRUPT = 1,  // Wait can't be interrupted.

  // Don't check for pending signals before waiting.  Generally
  // SWAIT_NO_INTERRUPT should be used instead, unless the thread/process itself
  // is locked.
  SWAIT_NO_SIGNAL_CHECK = 2,
} swait_flags_t;

// Universal scheduler wait function.  Called by variants below.  At most one
// lock type must be supplied.
int scheduler_wait(kthread_queue_t* queue, swait_flags_t flags, long timeout_ms,
                   kmutex_t* mu, kspinlock_t* sp);

// Wait on the given thread queue.
//
// The current thread is enqueued on the given queue, and another thread from
// the run queue will be chosen to run.  This thread won't continue (i.e., this
// function will block) until another thread or interrupt removes it from the
// queue and calles scheduler_make_runnable() on it.
void scheduler_wait_on(kthread_queue_t* queue);

#define SWAIT_DONE 0
#define SWAIT_INTERRUPTED 1
#define SWAIT_TIMEOUT 2

// As above, but can be interrupted by a signal delivered to the thread or a
// timeout.  If timeout_ms < 0, no timeout is set.  Returns SWAIT_INTERRUPTED if
// the wait was interrupted, SWAIT_TIMEOUT if the timeout expired, or SWAIT_DONE
// otherwise.
int scheduler_wait_on_interruptable(kthread_queue_t* queue, long timeout_ms);

// As above, but atomically unlocks the given mutex while starting to wait, and
// re-locks when woken.  In other words, treats the queue as a condition
// variable.
//
// Always interruptable.  Returns as scheduler_wait_on_interruptable().
int scheduler_wait_on_locked(kthread_queue_t* queue, long timeout_ms,
                             kmutex_t* mu);
int scheduler_wait_on_plocked(kthread_queue_t* queue, long timeout_ms,
                             pmutex_t* mu);

// As above, but with a spinlock rather than a mutex.
int scheduler_wait_on_splocked(kthread_queue_t* queue, long timeout_ms,
                               kspinlock_t* sp) REQUIRES(sp);

// Wake one thread waiting on the given thread queue.
void scheduler_wake_one(kthread_queue_t* queue);

// Wake *all* threads waiting on the given thread queue.
void scheduler_wake_all(kthread_queue_t* queue);

// Disable preemption for the current thread.  This stacks with previous calls
// (must be paired with sched_restore_preemption()).
//
// Preemption state follows the current thread (for example, if the current
// thread yields after calling this another thread may be scheduled with
// preemption enabled).
void sched_disable_preemption(void);

// Restore the previous preemption state from before the paired
// sched_disable_preemption() call.
void sched_restore_preemption(void);

// Enables preemption.  Should only be used when a thread is created.
void sched_enable_preemption_for_test(void);

// Returns true if preemption is enabled in the current thread.
bool sched_preemption_enabled(void);

// Tick the scheduler.  Called from an interrupt context.
void sched_tick(void);

// Special hook to do a TSAN acquire of the scheduler lock state on thread
// start.
void scheduler_tsan_acquire(void);

#endif
