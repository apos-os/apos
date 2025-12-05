// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_TEST_PROC_TEST_UTIL_H
#define APOO_TEST_PROC_TEST_UTIL_H

#include <stdbool.h>

#include "proc/notification.h"
#include "proc/process.h"
#include "user/include/apos/posix_types.h"

typedef struct {
  kpid_t zombie;  // The PID of the zombie.

  // Internal state.
  kpid_t parent_pid;
  bool uber_zombie;
  void (*func)(void*);
  void* func_arg;
  notification_t child_started;
  notification_t parent_can_wait;
  notification_t parent_wait_done;
  process_t* child_proc;
} ptu_zombie_t;

// Creates a zombie process for use in a test, along with a parent process that
// has not yet reclaimed it.  The child process will run the given function then
// exit.  If |uber_zombie| is true, then the parent will be set up to be blocked
// in the middle of process cleanup.
//
// The caller must call ptu_zombie_cleanup() on the result from the same process
// that called ptu_zombie_create().
ptu_zombie_t* ptu_zombie_create(bool uber_zombie, void (*func)(void*),
                                void* arg);

// Clean up zombie state.  Must be called from the same process as called
// ptu_zombie_create().
void ptu_zombie_cleanup(ptu_zombie_t* zombie);

#endif
