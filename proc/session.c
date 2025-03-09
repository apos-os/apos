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

// TODO(aoates): this (as well as the process group table) will be extremely
// sparse.  Use a hashtable or something instead.
static proc_session_t g_session_table[PROC_MAX_PROCS]
    GUARDED_BY(g_proc_table_lock);

kpid_t proc_setsid(void) {
  process_t* proc = proc_current();
  kspin_lock(&g_proc_table_lock);
  if (proc->pgroup == proc->id) {
    kspin_unlock(&g_proc_table_lock);
    return -EPERM;
  }

  proc_group_t* pgroup = proc_group_get(proc->id);
  setpgid_force(proc, proc->id, pgroup);

  pgroup->session = proc->id;

  proc_session_t* session = proc_session_get(proc->id);
  session->ctty = PROC_SESSION_NO_CTTY;
  session->fggrp = -1;
  kspin_unlock(&g_proc_table_lock);

  return proc->id;
}

kpid_t proc_getsid(kpid_t pid) {
  if (pid == 0) pid = proc_current()->id;

  process_t* proc = proc_get_ref(pid);
  if (!proc) return -ESRCH;

  kspin_lock(&g_proc_table_lock);
  int result = proc_getsid_locked(proc);
  kspin_unlock(&g_proc_table_lock);
  proc_put(proc);

  return result;
}

kpid_t proc_getsid_locked(process_t* proc) {
  kspin_assert_is_held(&g_proc_table_lock);
  proc_group_t* pgroup = proc_group_get(proc->pgroup);

  proc_group_t* cur_pgroup = proc_group_get(proc_current()->pgroup);
  if (pgroup->session != cur_pgroup->session) return -EPERM;

  return pgroup->session;
}

proc_session_t* proc_session_get(ksid_t sid) {
  if (sid < 0 || sid >= PROC_MAX_PROCS) {
    return NULL;
  }

  return &g_session_table[sid];
}
