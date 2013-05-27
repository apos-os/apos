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

#include "proc/kthread.h"

// Initialize the scheduler.
void scheduler_init(void);

// Add the given thread to the run queue.
void scheduler_make_runnable(kthread_t thread);

// Yield to another thread on the run queue.  The current thread is
// automatically re-added to the back of the run queue.
//
// Equivalent (logically) to scheduler_wait_on(RUN_QUEUE).
void scheduler_yield(void);

// Wait on the given thread queue.
//
// The current thread is enqueued on the given queue, and another thread from
// the run queue will be chosen to run.  This thread won't continue (i.e., this
// function will block) until another thread or interrupt removes it from the
// queue and calles scheduler_make_runnable() on it.
void scheduler_wait_on(kthread_queue_t* queue);

// Wake one thread waiting on the given thread queue.
void scheduler_wake_one(kthread_queue_t* queue);

// Wake *all* threads waiting on the given thread queue.
void scheduler_wake_all(kthread_queue_t* queue);

#endif
