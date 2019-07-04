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

#include "common/types.h"

typedef struct kthread_data* kthread_t;
#define KTHREAD_NO_THREAD 0x0

// Initialize the kthreads package.
void kthread_init(void);

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

/******************************* Thread Queues ********************************/

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

// Removes the given thread from the list its on.
void kthread_queue_remove(kthread_t thread);

/********************************* Mutexes ************************************/

struct kmutex {
  int locked;
  kthread_t holder; // For debugging.
  kthread_queue_t wait_queue;
};
typedef struct kmutex kmutex_t;

// Initialize the given mutex.
void kmutex_init(kmutex_t* m);

// Lock the given mutex, blocking until the lock is acquired.
void kmutex_lock(kmutex_t* m);

// Unlock the mutex.
void kmutex_unlock(kmutex_t* m);

// As above, but will never yield.  Only used internally to kthread and the
// scheduler.
void kmutex_unlock_no_yield(kmutex_t* m);

// Returns non-zero if the mutex is currently locked.
int kmutex_is_locked(kmutex_t* m);

// Asserts that the mutex is currently held by this thread.
// Note: may have false negatives in non-debug builds, where we don't track
// which thread is holding a mutex.
void kmutex_assert_is_held(kmutex_t* m);
void kmutex_assert_is_not_held(kmutex_t* m);

// An auto-unlocking mutex lock.
//
// Example usage:
//  {
//    KMUTEX_AUTO_LOCK(my_x_lock, &x->lock);
//    ...
//    // x->lock is automatically unlocked here when my_x_lock goes out of
//    // scope.
//  }
static inline kmutex_t* _kmutex_autolock_lock(kmutex_t* m) {
  kmutex_lock(m);
  return m;
}
static inline void _kmutex_autolock_unlock(kmutex_t** m) {
  kmutex_unlock(*m);
}
#define KMUTEX_AUTO_LOCK(name, lock) \
  kmutex_t* name __attribute__((cleanup(_kmutex_autolock_unlock))) = \
    _kmutex_autolock_lock(lock); \
  (void)name; \

#endif
