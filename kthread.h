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
#ifndef APOO_KTHREAD_T
#define APOO_KTHREAD_T

struct kthread;

// A linked list of kthreads.
typedef struct {
  struct kthread* head;
  struct kthread* tail;
} kthread_list_t;

// NOTE: if you update this structure, make sure you update kthread_asm.s as
// well.
struct kthread {
  uint32_t id;
  uint32_t active;  // Redundant with g_current_thread.
  uint32_t esp;
  void* retval;
  struct kthread* prev;
  struct kthread* next;
  uint32_t* stack;  // The block of memory allocated for the thread's stack.
  kthread_list_t join_list;  // List of thread's join()'d to this one.
};
typedef struct kthread kthread_t;

// Initialize the kthreads.
void kthread_init();

// Create a new thread and put it on the run queue.  The new thread will start
// in start_routine, with arg passed.
//
// RETURNS: 0 if unable to create the thread.
int kthread_create(kthread_t* thread, void *(*start_routine)(void*), void *arg);

// Join the given thread.  Will return once the other thread has exited
// (implicitly or explicitly), and return's the thread's return value.
void* kthread_join(kthread_t* thread);

// Explicitly yield to another thread.  The scheduler may choose this thread to
// run immediately, however.
void kthread_yield();

// Exits the current thread, setting it's return value to x.
void kthread_exit(void* x);

#endif
