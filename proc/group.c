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
#include "common/kassert.h"
#include "proc/process.h"

// Process groups.  Each element of the table is a list of processes in that
// group.
proc_group_t g_proc_group_table[PROC_MAX_PROCS];

kpid_t getpgid(kpid_t pid) {
  if (pid < 0 || pid >= PROC_MAX_PROCS) {
    return -EINVAL;
  }
  process_t* proc = (pid == 0) ? proc_current() : proc_get_ref(pid);
  if (!proc) {
    return -ESRCH;
  }

  if (proc_group_get(proc->pgroup)->session !=
      proc_group_get(proc_current()->pgroup)->session) {
    if (pid != 0) proc_put(proc);
    return -EPERM;
  }

  kpid_t result = proc->pgroup;
  if (pid != 0) proc_put(proc);
  return result;
}

int setpgid(kpid_t pid, kpid_t pgid) {
  if (pgid < 0 || pgid >= PROC_MAX_PROCS) {
    return -EINVAL;
  }

  if (pid == 0) pid = proc_current()->id;
  if (pgid == 0) pgid = pid;

  process_t* proc = proc_get_ref(pid);
  if (!proc || (proc != proc_current() && proc->parent != proc_current())) {
    if (proc) proc_put(proc);
    return -ESRCH;
  }

  proc_group_t* cur_pgroup = proc_group_get(proc->pgroup);
  if (cur_pgroup->session == proc->id) {  // Is session leader?
    proc_put(proc);
    return -EPERM;
  }

  proc_group_t* my_pgroup = proc_group_get(proc_current()->pgroup);
  if (cur_pgroup->session != my_pgroup->session) {
    proc_put(proc);
    return -EPERM;  // Child, but in a different session.
  }

  proc_group_t* pgroup = proc_group_get(pgid);
  if (pgid != pid &&
      (list_empty(&pgroup->procs) || pgroup->session != my_pgroup->session)) {
    proc_put(proc);
    return -EPERM;
  }

  if (proc->parent == proc_current() && proc->execed) {
    proc_put(proc);
    return -EACCES;
  }

  // If this is a newly-created process group, set its session to the same as
  // the old process group.
  if (list_empty(&pgroup->procs)) {
    KASSERT_DBG(pid == pgid);
    pgroup->session = proc_group_get(proc->pgroup)->session;
  }

  // Remove the process from its current group and add it to the new one.
  list_remove(&proc_group_get(proc->pgroup)->procs, &proc->pgroup_link);
  list_push(&pgroup->procs, &proc->pgroup_link);
  proc->pgroup = pgid;

  proc_put(proc);
  return 0;
}

proc_group_t* proc_group_get(kpid_t gid) {
  if (gid < 0 || gid >= PROC_MAX_PROCS)
    return NULL;
  else
    return &g_proc_group_table[gid];
}
