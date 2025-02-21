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

// Functions and syscalls for manipulating process groups.
#ifndef APOO_PROC_GROUP_H
#define APOO_PROC_GROUP_H

#include "common/list.h"
#include "proc/process.h"
#include "user/include/apos/posix_types.h"

typedef struct {
  // The processes in the group.
  list_t procs;

  // The session of the group.
  ksid_t session;
} proc_group_t;

// Return the given process's process group, as per getpgid(2).
//
// Returns the process group ID on success, or -errno on error.
kpid_t getpgid(kpid_t pid);

// Set the given process's process group, as per setpgid(2).
//
// Returns 0 on success, or -errno on error.
int setpgid(kpid_t pid, kpid_t pgid);

// Kernel-internal version of the above that mechanically sets the process group
// unconditionally (bypassing all policy checks).
void setpgid_force(process_t* proc, kpid_t pgid, proc_group_t* pgroup);

// Return the process group with the given ID.
proc_group_t* proc_group_get(kpid_t gid);

#endif
