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

#ifndef APOO_SANITIZERS_TSAN_TSAN_THREAD_H
#define APOO_SANITIZERS_TSAN_TSAN_THREAD_H

#include "proc/kthread.h"
#include "sanitizers/tsan/internal_types.h"
#include "sanitizers/tsan/tsan_event.h"
#include "sanitizers/tsan/vector_clock.h"

// Per-thread TSAN state.
typedef struct {
  tsan_vc_t clock;  // The thread's vector clock (i.e. when it last synchronized
                    // with all other active threads).
  tsan_tid_t tid;   // The unique thread ID.  TODO(tsan): is this needed?
  tsan_sid_t sid;   // The thread's slot.
  tsan_event_log_t log;
} tsan_thread_data_t;

// Call when a thread is created.  Allocates a TSAN slot ID and initializes the
// appropriate data structures.
void tsan_thread_create(kthread_t thread);

// Call when a thread is destroyed.
void tsan_thread_destroy(kthread_t thread);

// Call when a thread is joined.
void tsan_thread_join(kthread_t joined);

// Convert a slot ID into the corresponding kthread.
kthread_t tsan_get_thread(tsan_sid_t sid);

// Returns true if the given sid corresponds to a special stack-stomping thread
// (e.g. interrupt or defint virtual thread).
bool tsan_is_stack_stomper(tsan_sid_t sid);

#endif
