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
#include "sanitizers/tsan/tsan_thread.h"

#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "proc/kthread-internal.h"
#include "proc/kthread.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/internal_types.h"
#include "sanitizers/tsan/tsan_lock.h"
#include "sanitizers/tsan/vector_clock.h"

// A single thread slot.
typedef struct {
  kthread_t thread;  // Slot's current thread, or NULL.

  // Latest epoch for this slot (survives across reuse).  Not relevant except at
  // thread assignment.
  tsan_epoch_t epoch;
} tsan_tslot_t;

// Interrupts and defints are modeled as a per-CPU special virtual thread for
// each.  These are handled specially --- when synchronized with, they only
// synchronize the virtual thread itself, not its full vector clock.  That means
// that accesses between a normal thread and a special thread will be
// synchronized, but two normal threads cannot synchronize transitively via the
// special thread.  This is not a correctness/safety issue, but means that
// normal threads must use other synchronization constructs (locks, the
// scheduler implicit lock, etc) to synchronize between each other.
typedef struct {
  // TODO(tsan): implement defints
  kthread_t interrupt_thread;
} tsan_cpu_data_t;

// TODO(tsan): protect these slots from concurrent access.  If we only access
// this during thread creation and destruction (should confirm), a simple
// preemption lock (and later SMP-mutex) is sufficient.
static tsan_tslot_t g_tsan_slots[TSAN_THREAD_SLOTS];

// TODO(SMP): make this per-CPU.
static tsan_cpu_data_t g_tsan_cpu;

static tsan_cpu_data_t* get_cpu_data(void) {
  return &g_tsan_cpu;
}

// Body for the virtual interrupt/defint threads, which should never actually
// run --- it exists only as a data structure.
static void* tsan_special_thread_body(void* arg) {
  die("Should not be run");
}

void tsan_per_cpu_init(void) {
  KASSERT(0 == kthread_create(&g_tsan_cpu.interrupt_thread,
                              &tsan_special_thread_body, NULL));
  KASSERT(g_tsan_cpu.interrupt_thread != NULL);
}

kthread_t tsan_current_thread(void) {
  switch (kthread_execution_context()) {
    case KTCTX_THREAD:
    case KTCTX_DEFINT:
      return kthread_current_thread();

    case KTCTX_INTERRUPT:
      return get_cpu_data()->interrupt_thread;
  }
}

void tsan_thread_create(kthread_t thread) {
  // Find a free slot.
  int sid;
  for (sid = 0; sid < TSAN_THREAD_SLOTS; ++sid) {
    if (g_tsan_slots[sid].thread == NULL) break;
  }
  if (sid >= TSAN_THREAD_SLOTS) {
    die("TSAN: too many concurrent threads (ran out of slots)");
  }

  KASSERT_DBG(kthread_execution_context() == KTCTX_THREAD);
  g_tsan_slots[sid].thread = thread;
  tsan_vc_init(&thread->tsan.clock);
  kthread_t me = kthread_current_thread();
  if (me) {
    tsan_vc_acquire(&thread->tsan.clock, &me->tsan.clock);
    // TODO(tsan): this should be redundant with other atomic operations done in
    // the parent --- remove when that's the case.
    tsan_thread_epoch_inc(me);
  }
  thread->tsan.sid = sid;
  thread->tsan.tid = thread->id;
  thread->tsan.clock.ts[sid] = g_tsan_slots[sid].epoch;
  tsan_thread_epoch_inc(thread);
}

void tsan_thread_destroy(kthread_t thread) {
  KASSERT(thread->tsan.tid == thread->id);
  KASSERT(thread->tsan.sid >= 0);
  KASSERT(thread->tsan.sid < TSAN_THREAD_SLOTS);
  KASSERT(g_tsan_slots[thread->tsan.sid].thread == thread);

  int sid = thread->tsan.sid;
  // The epoch must have advanced at least once.
  KASSERT(thread->tsan.clock.ts[sid] > g_tsan_slots[sid].epoch);
  g_tsan_slots[sid].epoch = thread->tsan.clock.ts[sid];
  g_tsan_slots[sid].thread = NULL;
  kmemset(&thread->tsan, 0, sizeof(thread->tsan));
}

// TODO(tsan): protect all of these from interrupts, defints, and other
// concurrent accesses.
void tsan_thread_join(kthread_t joined) {
  KASSERT_DBG(kthread_execution_context() == KTCTX_THREAD);
  kthread_t me = kthread_current_thread();
  tsan_vc_acquire(&me->tsan.clock, &joined->tsan.clock);
}

void tsan_lock_init(tsan_lock_data_t* lock) {
  KASSERT_DBG(kthread_execution_context() == KTCTX_THREAD ||
              kthread_execution_context() == KTCTX_DEFINT);
  tsan_vc_init(&lock->clock);
  kthread_t thread = kthread_current_thread();
  if (thread) {
    // TODO(tsan): write a test for this.
    tsan_vc_acquire(&lock->clock, &thread->tsan.clock);
  }
}

void tsan_acquire(tsan_lock_data_t* lock, tsan_lock_type_t type) {
  if (!g_tsan_init) return;

  KASSERT(type == TSAN_LOCK || type == TSAN_INTERRUPTS);
  kthread_t thread = tsan_current_thread();
  switch (type) {
    case TSAN_LOCK:
      tsan_vc_acquire(&thread->tsan.clock, &lock->clock);
      break;

    case TSAN_INTERRUPTS: {
      KASSERT_DBG(lock == NULL);
      // Acquire only the interrupt thread's clock --- only writes made in an
      // interrupt context are now considered synchronized.
      PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
      tsan_sid_t int_sid = get_cpu_data()->interrupt_thread->tsan.sid;
      thread->tsan.clock.ts[int_sid] =
          max(thread->tsan.clock.ts[int_sid],
              get_cpu_data()->interrupt_thread->tsan.clock.ts[int_sid]);
      POP_INTERRUPTS_NO_TSAN();
      break;
    }
  }
}

void tsan_release(tsan_lock_data_t* lock, tsan_lock_type_t type) {
  if (!g_tsan_init) return;

  KASSERT(type == TSAN_LOCK || type == TSAN_INTERRUPTS);
  kthread_t thread = tsan_current_thread();
  // Publish all our values (and transitive ones) to the lock.
  switch (type) {
    case TSAN_LOCK:
      tsan_vc_acquire(&lock->clock, &thread->tsan.clock);
      break;

    case TSAN_INTERRUPTS: {
      KASSERT_DBG(lock == NULL);
      // Synchronize only my values to the interrupt thread.  Note: this is
      // incorrect!  We should in theory publish _all_ values I have seen to
      // the interrupt thread.  However that's redundant currently --- for me to
      // have seen a value from another thread, that thread must also have
      // synchronized with the interrupt thread.  Therefore I'm leaving this
      // more limited version in place for now, in case I'm wrong about that,
      // to avoid over-synchronization.  If I find a counter example, that
      // becomes my test case.
      PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
      tsan_sid_t my_sid = thread->tsan.sid;
      get_cpu_data()->interrupt_thread->tsan.clock.ts[my_sid] =
          max(thread->tsan.clock.ts[my_sid],
              get_cpu_data()->interrupt_thread->tsan.clock.ts[my_sid]);
      POP_INTERRUPTS_NO_TSAN();
      break;
    }
  }
  // Make sure all future writes are _not_ considered published.
  tsan_thread_epoch_inc(thread);
}
