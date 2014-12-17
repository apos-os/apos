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
#include "proc/group.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/tcgroup.h"
#include "vfs/vfs.h"

// Get the session of the current process and verify that the given fd is the
// session's controlling terminal.  Returns 0 on success, or -error.
static int check_fd(int fd, sid_t* sid_out, proc_session_t** session_out) {
  apos_stat_t stat;
  int result = vfs_fstat(fd, &stat);
  if (result) {
    return result;
  }

  *sid_out = proc_group_get(getpgid(0))->session;
  *session_out = proc_session_get(*sid_out);

  if (!VFS_S_ISCHR(stat.st_mode) || major(stat.st_rdev) != DEVICE_MAJOR_TTY ||
      minor(stat.st_rdev) != (unsigned int)(*session_out)->ctty) {
    return -ENOTTY;
  }

  return 0;
}

int proc_tcsetpgrp(int fd, pid_t pgid) {
  sid_t sid;
  proc_session_t* session = NULL;
  int result = check_fd(fd, &sid, &session);
  if (result) {
    return result;
  }

  // TODO(aoates): check if the process group is orphaned and SIGTTOU isn't
  // blocked or ignored, and return EIO.

  proc_group_t* pgroup = proc_group_get(pgid);
  if (!pgroup) {
    return -EINVAL;
  }

  if (list_empty(&pgroup->procs) || pgroup->session != sid) {
    return -EPERM;
  }

  const pid_t my_pgid = getpgid(0);
  if (my_pgid != session->fggrp) {
    if (proc_signal_deliverable(kthread_current_thread(), SIGTTOU)) {
      proc_force_signal_group(my_pgid, SIGTTOU);
      return -EINTR;  // TODO(aoates): is this correct?
    }
  }

  session->fggrp = pgid;
  return 0;
}

int proc_tcgetpgrp(int fd) {
  sid_t sid;
  proc_session_t* session = NULL;
  int result = check_fd(fd, &sid, &session);
  if (result) {
    return result;
  }

  if (session->fggrp < 0)
    return PROC_NO_FGGRP;
  else
    return session->fggrp;
}

pid_t proc_tcgetsid(int fd) {
  sid_t sid;
  proc_session_t* session = NULL;
  int result = check_fd(fd, &sid, &session);
  if (result) {
    return result;
  }

  KASSERT_DBG(sid == proc_getsid(0));
  return sid;
}
