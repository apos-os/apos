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

// Internal data structures used by the threading and scheduler packages.
#ifndef APOO_KTHREAD_INTERNAL_H
#define APOO_KTHREAD_INTERNAL_H

#include <stdint.h>

#define KTHREAD_RUNNING 0 // Currently running.
#define KTHREAD_PENDING 1 // Waiting on a run queue of some sort.
#define KTHREAD_DONE    2 // Finished.

// NOTE: if you update this structure, make sure you update kthread_asm.s as
// well.
struct kthread_data {
  uint32_t id;
  uint32_t state;
  uint32_t esp;
  void* retval;
  struct kthread_data* prev;
  struct kthread_data* next;
  uint32_t* stack;  // The block of memory allocated for the thread's stack.
  kthread_queue_t join_list;  // List of thread's join()'d to this one.
};
typedef struct kthread_data kthread_data_t;

#endif
