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

#include "common/errno.h"
#include "common/klog.h"
#include "proc/group.h"
#include "proc/process.h"
#include "proc/session.h"

pid_t proc_setsid(void) {
  process_t* proc = proc_current();
  if (proc->pgroup == proc->id) return -EPERM;

  int result = setpgid(0, 0);
  if (result) {
    klogfm(KL_PROC, DFATAL, "setpgid() failed in setsid(): %d\n", result);
    return result;
  }

  proc_group_t* pgroup = proc_group_get(proc->pgroup);
  pgroup->session = proc->id;

  // TODO(aoates): reset the controlling terminal.

  return 0;
}

pid_t proc_getsid(pid_t pid) {
  if (pid == 0) pid = proc_current()->id;

  process_t* proc = proc_get(pid);
  if (!proc) return -ESRCH;

  proc_group_t* pgroup = proc_group_get(proc->pgroup);
  proc_group_t* cur_pgroup = proc_group_get(proc_current()->pgroup);
  if (pgroup->session != cur_pgroup->session) return -EPERM;

  return pgroup->session;
}
