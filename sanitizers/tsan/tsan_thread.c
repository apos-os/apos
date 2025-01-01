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

// TODO(tsan): protect these slots from concurrent access.  If we only access
// this during thread creation and destruction (should confirm), a simple
// preemption lock (and later SMP-mutex) is sufficient.
static tsan_tslot_t g_tsan_slots[TSAN_THREAD_SLOTS];

void tsan_thread_create(kthread_t thread) {
  // Find a free slot.
  int sid;
  for (sid = 0; sid < TSAN_THREAD_SLOTS; ++sid) {
    if (g_tsan_slots[sid].thread == NULL) break;
  }
  if (sid >= TSAN_THREAD_SLOTS) {
    die("TSAN: too many concurrent threads (ran out of slots)");
  }

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
  kthread_t me = kthread_current_thread();
  tsan_vc_acquire(&me->tsan.clock, &joined->tsan.clock);
}

void tsan_lock_init(tsan_lock_data_t* lock) {
  tsan_vc_init(&lock->clock);
  kthread_t thread = kthread_current_thread();
  if (thread) {
    // TODO(tsan): write a test for this.
    tsan_vc_acquire(&lock->clock, &thread->tsan.clock);
  }
}

void tsan_acquire(tsan_lock_data_t* lock, tsan_lock_type_t type) {
  KASSERT(type == TSAN_LOCK);
  kthread_t thread = kthread_current_thread();
  tsan_vc_acquire(&thread->tsan.clock, &lock->clock);
}

void tsan_release(tsan_lock_data_t* lock, tsan_lock_type_t type) {
  KASSERT(type == TSAN_LOCK);
  kthread_t thread = kthread_current_thread();
  // Publish all our values (and transitive ones) to the lock.
  tsan_vc_acquire(&lock->clock, &thread->tsan.clock);
  // Make sure all future writes are _not_ considered published.
  tsan_thread_epoch_inc(thread);
}
