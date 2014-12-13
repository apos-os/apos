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

#include "proc/group.h"

#include "common/errno.h"
#include "proc/process.h"

// Process groups.  Each element of the table is a list of processes in that
// group.
proc_group_t g_proc_group_table[PROC_MAX_PROCS];

pid_t getpgid(pid_t pid) {
  if (pid < 0 || pid >= PROC_MAX_PROCS) {
    return -EINVAL;
  }
  process_t* proc = (pid == 0) ? proc_current() : proc_get(pid);
  if (!proc) {
    return -ESRCH;
  }

  return proc->pgroup;
}

int setpgid(pid_t pid, pid_t pgid) {
  if (pgid < 0 || pgid >= PROC_MAX_PROCS) {
    return -EINVAL;
  }

  if (pid == 0) pid = proc_current()->id;
  if (pgid == 0) pgid = pid;

  process_t* proc = proc_get(pid);
  // TODO(aoates): check if the process is a session leader.
  if (!proc || (proc != proc_current() && proc->parent != proc_current())) {
    return -ESRCH;
  }

  list_t* pgroup = &proc_group_get(pgid)->procs;
  // TODO(aoates): test if any of the processes in the group are in the current
  // session.
  if (pgid != pid && list_empty(pgroup)) {
    return -EPERM;
  }

  if (proc->parent == proc_current() && proc->execed) {
    return -EACCES;
  }

  // Remove the process from its current group and add it to the new one.
  list_remove(&proc_group_get(proc->pgroup)->procs, &proc->pgroup_link);
  list_push(pgroup, &proc->pgroup_link);
  proc->pgroup = pgid;

  return 0;
}

proc_group_t* proc_group_get(pid_t gid) {
  if (gid < 0 || gid >= PROC_MAX_PROCS)
    return NULL;
  else
    return &g_proc_group_table[gid];
}
