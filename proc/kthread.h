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

// Kernel threads package.
//
// The package is in two parts: kthreads (this), which provides the threading
// primitives (threads, handles, thread queues); and the scheduler (see
// scheduler.h/c), which is responsible for actually running and scheduling
// threads.
#ifndef APOO_KTHREAD_T
#define APOO_KTHREAD_T

#include <stdbool.h>

#include "common/attributes.h"
#include "common/config.h"
#include "common/list.h"
#include "common/types.h"
#include "dev/timer.h"
#include "proc/thread_annotations.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_lock.h"
#endif

typedef struct kthread_data* kthread_t;
#define KTHREAD_NO_THREAD 0x0

// Initialize the kthreads package.
void kthread_init(void);

// Return a handle to the currently running thread.
kthread_t kthread_current_thread(void);

// Create a new thread.  The new thread will start in start_routine, with arg
// passed.  The new thread is NOT automatically made runnable --- you must call
// scheduler_make_runnable(...) on it after creation if you want it to run.
//
// All threads should be either joined (with kthread_join()), from another
// thread, or detached (with kthread_detach()).  Not doing so will leak
// resources.
//
// The created thread is a raw kernel thread, unattached to any process.  It
// must not reference user memory, file descriptors, etc.  To create a process
// thread, use proc_thread_create().
//
// Note: the kthread_t given is just a handle to the thread --- if it goes out
// of scope or is overwritten, the thread will continue unhindered.
//
// RETURNS: 0 if successful, or -errno if unable to create the thread.
int kthread_create(kthread_t* thread, void *(*start_routine)(void*), void *arg);

// Join the given thread.  Will return once the other thread has exited
// (implicitly or explicitly), and return's the thread's return value.
//
// Note: since the join()'ing thread cleans up the join()'ed threads data, it's
// not safe for multiple threads to join() on a single other thread, UNLESS they
// all call kthread_join() before the target thread has been scheduled.
void* kthread_join(kthread_t thread);

// Returns true if the other thread has exited (i.e. kthread_join() will return
// without blocking).
bool kthread_is_done(kthread_t thread);

// Detach the given thread.  When the thread exits, its resources will be
// collected immediately.
//
// Note that a detached thread cannot be join()'d (doing so will KASSERT(0)).
void kthread_detach(kthread_t thread);

// Exits the current thread, setting it's return value to x.
void kthread_exit(void* x);

// Run the given function on all threads in the kernel.  Use sparingly, must not
// block.
void kthread_run_on_all(void (*f)(kthread_t, void*), void* arg);

// Disable or re-enable a thread.  A disabled thread will be schedulable but
// not run (return from a blocking scheduler function) until re-enabled.
void kthread_disable(kthread_t thread);
void kthread_enable(kthread_t thread);

typedef enum {
  // Running in a thread context (user or kernel).
  KTCTX_THREAD = 1,
  // Running in a defint context (could be inside an interrupt).
  KTCTX_DEFINT = 2,
  // Running in an interrupt context.
  KTCTX_INTERRUPT = 3,
} ktctx_type_t;

// Returns the current execution context we're running in.
ktctx_type_t kthread_execution_context(void);

#endif
