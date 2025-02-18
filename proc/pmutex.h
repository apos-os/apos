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

// A pmutex_t is essentially the same as a kmutex_t, except that it is
// guaranteed to not block if preemption is disabled.  It is therefore safe to
// use in both prempt-safe and non-prempt safe code.
//
// Internally, it accomplishes this by using a normal kmutex_t and also
// disabling preemption while locked.  So long as the calling code does not
// block while the mutex is locked, it will not be descheduled --- which means
// other threads are guaranteed not to need to block to acquire it.
//
// Once all code in the kernel is prempt-safe, all pmutex_ts can be converted
// into kmutex_ts.
#ifndef APOO_PROC_PMUTEX_H
#define APOO_PROC_PMUTEX_H

#include "proc/thread_annotations.h"
#include "proc/kthread.h"

typedef struct CAPABILITY("mutex") {
  kmutex_t _mu;
} pmutex_t;

// Initialize the given mutex.
void pmutex_init(pmutex_t* m);

// Lock the pmutex_t.  So long as no one blocks while holding the pmutex, this
// is guaranteed to not block.
void pmutex_lock(pmutex_t* mu) ACQUIRE(mu);

// Unlock the pmutex_t.  Guaranteed to not block.
void pmutex_unlock(pmutex_t* mu) RELEASE(mu);

// Returns true if the mutex is currently locked.
bool pmutex_is_locked(const pmutex_t* m);

// Asserts that the mutex is currently held by this thread.
// Note: may have false negatives in non-debug builds, where we don't track
// which thread is holding a mutex.
void pmutex_assert_is_held(const pmutex_t* m) ASSERT_CAPABILITY(m);
void pmutex_assert_is_not_held(const pmutex_t* m);

#endif
