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

typedef struct kthread_data* kthread_t;

// Initialize the kthreads package.
void kthread_init();

// Create a new thread.  The new thread will start in start_routine, with arg
// passed.  The new thread is NOT automatically made runnable --- you must call
// scheduler_make_runnable(...) on it after creation if you want it to run.
//
// All threads should be either joined (with kthread_join()), from another
// thread, or detached (with kthread_detach()).  Not doing so will leak
// resources.
//
// Note: the kthread_t given is just a handle to the thread --- if it goes out
// of scope or is overwritten, the thread will continue unhindered.
//
// RETURNS: 0 if unable to create the thread.
int kthread_create(kthread_t* thread, void *(*start_routine)(void*), void *arg);

// Join the given thread.  Will return once the other thread has exited
// (implicitly or explicitly), and return's the thread's return value.
//
// Note: since the join()'ing thread cleans up the join()'ed threads data, it's
// not safe for multiple threads to join() on a single other thread, UNLESS they
// all call kthread_join() before the target thread has been scheduled.
void* kthread_join(kthread_t thread);

// Detach the given thread.  When the thread exits, its resources will be
// collected immediately.
//
// Note that a detached thread cannot be join()'d (doing so will KASSERT(0)).
void kthread_detach(kthread_t thread);

// Exits the current thread, setting it's return value to x.
void kthread_exit(void* x);

// Thread queues are simple linked lists of threads, which can be pushed on the
// back and popped from the front.  A given thread can only be on a single
// thread queue (or no thread queues) at once --- trying to enqueue a thread on
// multiple queues will result in a panic.
typedef struct {
  kthread_t head;
  kthread_t tail;
} kthread_queue_t;

// Initialze a thread queue.
void kthread_queue_init(kthread_queue_t* queue);

// Returns 1 if the given thread queue is empty.
int kthread_queue_empty(kthread_queue_t* queue);

// Enqueue a thread on the back of the given thread queue.
void kthread_queue_push(kthread_queue_t* queue, kthread_t thread);

// Pops a thread off the front of the thread queue.
kthread_t kthread_queue_pop(kthread_queue_t* queue);

#endif
