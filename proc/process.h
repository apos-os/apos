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

// Kernel process management.
#ifndef APOO_PROCESS_H
#define APOO_PROCESS_H

#include "proc/kthread.h"

typedef struct process {
  int id;  // Index into global process table.
  kthread_t thread;  // Main process thread.
} process_t;

// Initialize the process table, and create the first process (process 0) from
// the current thread.
//
// REQUIRES: kthread_init() and scheduler_init().
void proc_init();

#endif
