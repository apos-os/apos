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
  apos_ms_t now = get_time_ms();
  list_t run = LIST_INIT;
  kspin_lock(&g_defint_timer_lock);
  list_link_t* curr = g_defint_timers.head;
  apos_ms_t next_time = APOS_MS_MAX;
  while (curr) {
    defint_timer_t* entry = container_of(curr, defint_timer_t, link);
    if (entry->deadline > now) {
      next_time = entry->deadline;
      break;
    }
    entry->started_run = true;
    list_remove(&g_defint_timers, curr);
    list_push(&run, curr);
    curr = g_defint_timers.head;
  }
  atomic_store_relaxed(&g_defint_timer_next, (uint32_t)next_time);
  kspin_unlock(&g_defint_timer_lock);

  while (!list_empty(&run)) {
    list_link_t* link = list_pop(&run);
    defint_timer_t* entry = container_of(link, defint_timer_t, link);
    entry->cb(entry, entry->cb_arg);
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
