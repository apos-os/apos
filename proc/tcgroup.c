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

#include "common/kassert.h"
#include "common/errno.h"
#include "dev/dev.h"
#include "dev/tty.h"
#include "dev/tty_util.h"
#include "proc/group.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/tcgroup.h"
#include "vfs/vfs.h"

int proc_tcsetpgrp(int fd, kpid_t pgid) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, true, &tty);
  if (result) return result;

  kspin_lock(&g_proc_table_lock);
  proc_group_t* pgroup = proc_group_get(pgid);
  if (!pgroup) {
    kspin_unlock(&g_proc_table_lock);
    return -EINVAL;
  }

  ksid_t sid = proc_getsid_locked(proc_current());
  if (list_empty(&pgroup->procs) || pgroup->session != sid) {
    kspin_unlock(&g_proc_table_lock);
    return -EPERM;
  }

  result = tty_check_write_locked(tty);
  if (result) {
    kspin_unlock(&g_proc_table_lock);
    return result;
  }

  proc_session_t* session = proc_session_get(sid);
  session->fggrp = pgid;
  kspin_unlock(&g_proc_table_lock);
  return 0;
}

int proc_tcgetpgrp(int fd) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, true, &tty);
  if (result) return result;

  kspin_lock(&g_proc_table_lock);
  proc_session_t* session = proc_session_get(tty->session);
  int fggrp = session->fggrp;
  kspin_unlock(&g_proc_table_lock);
  if (fggrp < 0)
    return PROC_NO_FGGRP;
  else
    return fggrp;
}

kpid_t proc_tcgetsid(int fd) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, true, &tty);
  if (result) return result;

  return tty->session;
}
