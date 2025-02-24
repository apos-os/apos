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
#include "dev/tty_util.h"

#include "common/errno.h"
#include "dev/tty.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "vfs/vfs.h"

int tty_get_fd(int fd, bool require_ctty, tty_t** tty) {
  apos_stat_t stat;
  int result = vfs_fstat(fd, &stat);
  if (result) {
    return result;
  }

  if (!VFS_S_ISCHR(stat.st_mode) || kmajor(stat.st_rdev) != DEVICE_MAJOR_TTY) {
    return -ENOTTY;
  }

  *tty = tty_get(stat.st_rdev);
  if (!tty) return -ENOTTY;

  if (require_ctty && (*tty)->session != proc_getsid(0)) {
    return -ENOTTY;
  }

  return 0;
}

int tty_check_read(const tty_t* tty) {
  const process_t* me = proc_current();
  kspin_lock(&g_proc_table_lock);
  const proc_group_t* my_pgroup = proc_group_get(me->pgroup);
  const proc_session_t* tty_session = proc_session_get(tty->session);
  int result = 0;
  if (tty->session == my_pgroup->session && me->pgroup != tty_session->fggrp) {
    result = -EIO;
    // TODO(aoates): this should be a process-wide check, not a thread one.
    if (proc_thread_signal_deliverable(kthread_current_thread(), SIGTTIN)) {
      proc_force_signal_group_locked(my_pgroup, SIGTTIN);
      result = -EINTR;
    }
  }
  kspin_unlock(&g_proc_table_lock);

  return result;
}

int tty_check_write(const tty_t* tty) {
  kspin_lock(&g_proc_table_lock);
  int result = tty_check_write_locked(tty);
  kspin_unlock(&g_proc_table_lock);
  return result;
}

int tty_check_write_locked(const tty_t* tty) {
  const process_t* me = proc_current();
  const proc_group_t* my_pgroup = proc_group_get(me->pgroup);

  if (tty->session != my_pgroup->session) {
    return 0;
  }
  const proc_session_t* session = proc_session_get(tty->session);

  // TODO(aoates): check if the process group is orphaned and SIGTTOU isn't
  // blocked or ignored, and return EIO.

  if (me->pgroup != session->fggrp) {
    // TODO(aoates): this should be a process-wide check, not a thread one.
    if (proc_thread_signal_deliverable(kthread_current_thread(), SIGTTOU)) {
      proc_force_signal_group_locked(my_pgroup, SIGTTOU);
      return -EINTR;
    }
  }

  return 0;
}
