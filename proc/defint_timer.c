// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "proc/defint_timer.h"

#include "common/atomic.h"
#include "common/kassert.h"
#include "common/list.h"
#include "dev/timer.h"
#include "proc/defint.h"
#include "proc/spinlock.h"

// Structure to hold timer data temporarily while the lock is released.
typedef struct {
  defint_timer_cb_t cb;
  defint_timer_t* timer;
  void* cb_arg;
} defint_timer_data_t;

kspinlock_t g_defint_timer_lock = KSPINLOCK_NORMAL_INIT_STATIC;
static list_t g_defint_timers GUARDED_BY(g_defint_timer_lock) =
    LIST_INIT_STATIC;

// Always set to the deadline of the first entry on the timer list.
static atomic32_t g_defint_timer_next = ATOMIC32_INIT(UINT32_MAX);

// Whether we have a timer defint pending or not.  Needed in case the timer
// defints run _very_ slowly (which can happen under TSAN).
static atomic32_t g_defint_timer_pending = ATOMIC32_INIT(0);

static void defint_timer_defint(void* arg) {
  atomic_store_relaxed(&g_defint_timer_pending, 0);

  const int kBlockSize = 10;
  defint_timer_data_t timers_to_run[kBlockSize];

  while (true) {
    apos_ms_t now = get_time_ms();
    apos_ms_t next_time = APOS_MS_MAX;

    kspin_lock(&g_defint_timer_lock);

    // Process up to kBlockSize timers at a time.
    int count = 0;
    list_link_t* curr = g_defint_timers.head;
    while (curr && count < kBlockSize) {
      list_link_t* next = curr->next; // Save next pointer before potential removal
      defint_timer_t* entry = container_of(curr, defint_timer_t, link);

      next_time = entry->deadline;
      if (entry->deadline > now) {
        break;
      }

      // Timer expired, copy data and remove from list
      entry->started_run = true;
      timers_to_run[count].cb = entry->cb;
      timers_to_run[count].timer = entry;
      timers_to_run[count].cb_arg = entry->cb_arg;
      list_remove(&g_defint_timers, curr);
      count++;

      curr = next;
    }

    atomic_store_relaxed(&g_defint_timer_next, (uint32_t)next_time);
    kspin_unlock(&g_defint_timer_lock);

    // If no timers were found to run in this iteration, we are done.
    if (count == 0) {
      break;
    }

    // Run the callbacks for the collected timers
    for (int i = 0; i < count; i++) {
      timers_to_run[i].cb(timers_to_run[i].timer, timers_to_run[i].cb_arg);
    }
  }
}

void defint_timer_run(apos_ms_t now) {
  // Relaxed is OK --- we won't actually read any dependent data without the
  // lock held.
  if (atomic_load_relaxed(&g_defint_timer_next) <= now &&
      !atomic_load_relaxed(&g_defint_timer_pending)) {
    atomic_store_relaxed(&g_defint_timer_pending, 1);
    defint_schedule(&defint_timer_defint, NULL);
  }
}

static inline ALWAYS_INLINE void init_handle(defint_timer_t* handle,
                                             apos_ms_t deadline_ms,
                                             defint_timer_cb_t cb, void* arg) {
  kspin_constructor(&g_defint_timer_lock);
  handle->deadline = deadline_ms;
  handle->cb = cb;
  handle->cb_arg = arg;
  handle->started_run = false;
  handle->link = LIST_LINK_INIT;
}

void defint_timer_create(apos_ms_t deadline_ms, defint_timer_cb_t cb, void* arg,
                         defint_timer_t* handle) {
  init_handle(handle, deadline_ms, cb, arg);

  kspin_lock(&g_defint_timer_lock);
  list_link_t* prev = NULL;
  list_link_t* curr = g_defint_timers.head;
  while (curr) {
    defint_timer_t* entry = container_of(curr, defint_timer_t, link);
    if (entry->deadline >= deadline_ms) {
      break;
    }
    prev = curr;
    curr = curr->next;
  }
  list_insert(&g_defint_timers, prev, &handle->link);
  if (prev == NULL) {
    // Relaxed is OK --- we won't actually read any dependent data without the
    // lock held.
    atomic_store_relaxed(&g_defint_timer_next, (uint32_t)deadline_ms);
  }
  kspin_unlock(&g_defint_timer_lock);
}

bool defint_timer_cancel(defint_timer_t* handle) {
  kspin_lock(&g_defint_timer_lock);
  if (handle->started_run) {
    kspin_unlock(&g_defint_timer_lock);
    return false;
  }
  list_remove(&g_defint_timers, &handle->link);
  // Don't bother updating the next timer value --- if this is the first time,
  // we'll just have a spurious (but harmless) defint run.
  kspin_unlock(&g_defint_timer_lock);
  return true;
}
