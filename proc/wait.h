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

#ifndef APOO_PROC_WAIT_H
#define APOO_PROC_WAIT_H

#include "proc/process.h"
#include "user/include/apos/wait.h"

// Wait until a child exits, and return its pid (and optionally its exit
// status).
kpid_t proc_wait(int* exit_status);

// As above, but respects pid and flags as per waitpid(2).
kpid_t proc_waitpid(kpid_t pid, int* exit_status, int options);

// Get a unique value identifying the process running on the given pid.  Assumes
// external synchronization of the process exiting (i.e. if the process exits
// during this call, the result is undefined).
// For tests.
uint32_t proc_get_procguid(kpid_t pid);

// Atomically wait until the pid is not attached to the given process guid.
// Unlike the actual wait() functions, doesn't do any cleanup --- just waits
// (via polling) until the process has exited and been cleaned up.
int proc_wait_guid(kpid_t pid, uint32_t guid, int timeout_ms);

#endif
