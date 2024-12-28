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

// A lightweight task run in a defint context, but level-triggered rather than
// edge-triggered, and with persistent per-tasklet state.
#ifndef APOO_PROC_TASKLET_H
#define APOO_PROC_TASKLET_H

#include "proc/spinlock.h"
struct tasklet;
typedef struct tasklet tasklet_t;

// A tasklet function.  It will be invoked with a pointer to the tasklet itself
// as well as the tasklet's argument.
typedef void (*tasklet_fn_t)(tasklet_t*, void*);

// Initialize a tasklet.  The given function will be called with the given
// argument whenever the tasklet is scheduled.
void tasklet_init(tasklet_t* tl, tasklet_fn_t fn, void* arg);

// Schedule a tasklet to be run soon.  If already scheduled, this is a no-op.
//
// Tasklets are run in a defint context, and therefore are disabled in the
// current thread automatically whenever a spinlock is held.
//
// Returns true if a new tasklet is scheduled, false if not.
//
// Interrupt-safe.
bool tasklet_schedule(tasklet_t* tl);

// Tasklet state.  Opaque to users.
struct tasklet {
  kspinlock_intsafe_t lock;
  tasklet_fn_t fn;
  void* arg;
  bool run;  // Whether it is scheduled to run.
};

#endif
