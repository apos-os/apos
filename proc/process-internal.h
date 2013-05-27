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

// Utilities and definitions for use inside the process module.
#ifndef APOO_PROC_PROCESS_INTERNAL_H
#define APOO_PROC_PROCESS_INTERNAL_H

#include "proc/process.h"

// Allocate and initialize a process, and assign it a free process ID.
// Returns NULL if the kernel is out of memory or process IDs.
process_t* proc_alloc(void);

// Destroy the given process_t and remove it from the process table.  It must
// have already been torn down (as per proc_exit() and proc_wait()).
void proc_destroy(process_t* process);

// Change the current process.
void proc_set_current(process_t* process);

#endif
