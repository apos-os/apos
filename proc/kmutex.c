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
#include "proc/kmutex.h"

#include "common/kassert.h"
#include "dev/interrupts.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/scheduler.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
static void init_deadlock_data(kmutex_t* m) {
  // TODO(aoates): this could cause a false positive if we recreate mutexes
  // quickly enough (such that IDs are reused).
  m->id = fnv_hash_concat(fnv_hash_addr((addr_t)m), get_time_ms());
  m->link = LIST_LINK_INIT;
  for (int i = 0 ;i < KMUTEX_DEADLOCK_LRU_SIZE; ++i) {
    m->priors[i].id = 0;
    m->priors[i].lru = 0;
  }
}
#endif

void kmutex_init(kmutex_t* m) {
  m->locked = 0;
  m->holder = 0x0;
  kthread_queue_init(&m->wait_queue);

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  init_deadlock_data(m);
#endif

#if ENABLE_TSAN
  tsan_lock_init(&m->tsan);
#endif
}

// No-op functions that allow us to avoid disabling thread safety analysis for
// the entire function (so we can still get it on any spinlocks, etc).
static inline ALWAYS_INLINE
void _kmutex_acq(kmutex_t* m) ACQUIRE(m) NO_THREAD_SAFETY_ANALYSIS {}
static inline ALWAYS_INLINE
void _kmutex_rel(kmutex_t* m) RELEASE(m) NO_THREAD_SAFETY_ANALYSIS {}

void kmutex_lock(kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  // We should never be blocking if we're holding a spinlock.
  KASSERT_DBG(kthread_current_thread()->spinlocks_held == 0);
  KASSERT_DBG(defint_running_state() == DEFINT_NONE);
  if (m->locked) {
    // Mutexes are non-reentrant, so this would deadlock.
    KASSERT_MSG(m->holder != kthread_current_thread(),
                "Mutexs are non-reentrant: cannot lock mutex already held by "
                "the current thread!");
    scheduler_wait_on(&m->wait_queue);
    KASSERT(m->holder == kthread_current_thread());
  } else {
    m->locked = 1;
    m->holder = kthread_current_thread();
  }
  KASSERT(m->locked == 1);

#if ENABLE_TSAN
  tsan_acquire(&m->tsan, TSAN_LOCK);
#endif
  POP_INTERRUPTS();

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  if (m->id == 0) {
    init_deadlock_data(m);
  }
  apos_ms_t now = get_time_ms();
  int lru_search_start = 0;
  FOR_EACH_LIST(link_iter, &kthread_current_thread()->mutexes_held) {
    const kmutex_t* locked_mu = LIST_ENTRY(link_iter, kmutex_t, link);

    // Check if this mutex is in the locked mutex's priors.
    // TODO(aoates): if the LRU size needs to be increased, consider adding a
    // bloom filter here for the fast path.
    for (int i = 0; i < KMUTEX_DEADLOCK_LRU_SIZE; ++i) {
      if (locked_mu->priors[i].id == m->id) {
        klogfm(KL_PROC, FATAL,
               "Possible mutex deadlock detected.  Mutex A (%xu) locked while "
               "mutex B (%xu) held; previously B was locked while A was held\n",
               m->id, locked_mu->id);
      }
    }

    // Add the locked mutex to _this_ mutex's priors for future checks.
    int lru_idx = lru_search_start;
    apos_ms_t lru = m->priors[lru_idx].lru;
    for (int i_rel = 0; i_rel < KMUTEX_DEADLOCK_LRU_SIZE; ++i_rel) {
      const int i = (lru_search_start + i_rel) % KMUTEX_DEADLOCK_LRU_SIZE;
      if (m->priors[i].id == locked_mu->id || m->priors[i].id == 0) {
        // Already in the priors set, or an empty slot.  No need to continue.
        lru_idx = i;
        break;
      } else if (m->priors[i].lru < lru) {
        lru_idx = i;
        lru = m->priors[i].lru;
      }
    }
    m->priors[lru_idx].id = locked_mu->id;
    m->priors[lru_idx].lru = now;
    // Next time, start the LRU search right after the current index, to avoid
    // O(n^2) inserts for the common case.
    lru_search_start = (lru_idx + 1) % KMUTEX_DEADLOCK_LRU_SIZE;
  }

  list_push(&kthread_current_thread()->mutexes_held, &m->link);
#endif
  _kmutex_acq(m);
}

static void kmutex_unlock_internal(kmutex_t* m, bool yield) RELEASE(m) {
#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  list_remove(&kthread_current_thread()->mutexes_held, &m->link);
#endif
  PUSH_AND_DISABLE_INTERRUPTS();
#if ENABLE_TSAN
  tsan_release(&m->tsan, TSAN_LOCK);
#endif

  KASSERT(m->locked == 1);
  KASSERT(m->holder == kthread_current_thread());
  if (!kthread_queue_empty(&m->wait_queue)) {
    // Try to find the first non-disabled waiter.
    kthread_t next_holder = m->wait_queue.head;
    while (next_holder && !next_holder->runnable) {
      next_holder = next_holder->next;
    }
    if (!next_holder) {
      next_holder = m->wait_queue.head;
    }
    kthread_queue_remove(next_holder);
    m->holder = next_holder;
    scheduler_make_runnable(next_holder);
    if (yield) scheduler_yield();
  } else {
    m->locked = 0;
    m->holder = 0x0;
  }
  POP_INTERRUPTS();
  _kmutex_rel(m);
}

void kmutex_unlock(kmutex_t* m) {
  kmutex_unlock_internal(m, true);
}

void kmutex_unlock_no_yield(kmutex_t* m) {
  kmutex_unlock_internal(m, false);
}

bool kmutex_is_locked(const kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  int is_locked = m->locked;
  POP_INTERRUPTS();
  return is_locked;
}

void kmutex_assert_is_held(const kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(m->locked == 1);
  KASSERT(m->holder == kthread_current_thread());
  POP_INTERRUPTS();
}

void kmutex_assert_is_not_held(const kmutex_t* m) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(m->holder != kthread_current_thread());
  POP_INTERRUPTS();
}
