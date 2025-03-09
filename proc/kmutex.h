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

#ifndef APOO_PROC_KMUTEX_H
#define APOO_PROC_KMUTEX_H

#include <stdbool.h>
#include <stdint.h>

#include "common/attributes.h"
#include "common/types.h"
#include "dev/timer.h"
#include "proc/kthread.h"
#include "proc/kthread-queue.h"
#include "proc/thread_annotations.h"

// How many locked mutexes to track for deadlock detection.
#define KMUTEX_DEADLOCK_LRU_SIZE 10

typedef uint32_t kmutex_id_t;
typedef struct {
  kmutex_id_t id;
  apos_ms_t lru;
} kmutex_prior_t;

struct CAPABILITY("mutex") kmutex {
  int locked;
  kthread_t holder; // For debugging.
  kthread_queue_t wait_queue;

#if ENABLE_KMUTEX_DEADLOCK_DETECTION
  kmutex_id_t id;
  list_link_t link;  // On holder list, for deadlock detection.
  // Mutexes that have been held when this was locked.
  kmutex_prior_t priors[KMUTEX_DEADLOCK_LRU_SIZE];
#endif

#if ENABLE_TSAN
  tsan_lock_data_t tsan;
#endif
};
typedef struct kmutex kmutex_t;

// Initialize the given mutex.  It is also valid to zero-init the mutex (in
// which case some portions might be lazy-initialized the first time the mutex
// is locked).  Zero-initialization should only be used for static global
// mutexes, not dynamically allocated ones.
void kmutex_init(kmutex_t* m);

// Lock the given mutex, blocking until the lock is acquired.
void kmutex_lock(kmutex_t* m) ACQUIRE(m);

// Unlock the mutex.
void kmutex_unlock(kmutex_t* m) RELEASE(m);

// As above, but will never yield.  Only used internally to kthread and the
// scheduler.
void kmutex_unlock_no_yield(kmutex_t* m) RELEASE(m);

// Returns non-zero if the mutex is currently locked.
bool kmutex_is_locked(const kmutex_t* m);

// Asserts that the mutex is currently held by this thread.
// Note: may have false negatives in non-debug builds, where we don't track
// which thread is holding a mutex.
void kmutex_assert_is_held(const kmutex_t* m) ASSERT_CAPABILITY(m);
void kmutex_assert_is_not_held(const kmutex_t* m);

// Claim the given mutex is locked for the purposes of construction or
// destruction of the protected data (and lock).
static inline ALWAYS_INLINE
void kmutex_constructor(const kmutex_t* l) ASSERT_CAPABILITY(l) {}
static inline ALWAYS_INLINE
void kmutex_destructor(const kmutex_t* l) ASSERT_CAPABILITY(l) {}

#endif
