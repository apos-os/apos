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
#include "common/kassert.h"
#include "dev/dev.h"
#include "dev/tty.h"
#include "proc/exit.h"
#include "proc/group.h"
#include "proc/kthread.h"
#include "proc/pmutex.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "vfs/vfs.h"

void proc_exit(int status) {
  process_t* const p = proc_current();
  kthread_t thread = kthread_current_thread();
  KASSERT(thread->process == p);
  KASSERT_DBG(list_link_on_list(&p->threads, &thread->proc_threads_link));
  KASSERT(p->state == PROC_RUNNING || p->state == PROC_STOPPED);

  if (p->id == 0) {
    die("Cannot exit() the root thread");
  }

  // Note: another thread might be simultaneously calling exit() and overwrite
  // this....that's fine.
  p->exit_status = status;

  // Prevent any new threads from being created.  In the last-thread-exits
  // scenario where proc_exit() isn't called, this is unnecessary because the
  // only thread that could be creating new threads is itself exiting.
  p->exiting = true;

  // Terminate all threads in the process, then exit this one (which will clean
  // up the process if it's the last one running).
  FOR_EACH_LIST(iter_link, &p->threads) {
    kthread_data_t* thread_iter =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    if (thread_iter == thread) continue;

    proc_force_signal_on_thread(p, thread_iter, SIGAPOSTKILL);
  }

  proc_thread_exit(NULL);
}

void proc_finish_exit(void) {
  // We must be the only thread remaining.
  process_t* const p = proc_current();
  KASSERT(list_empty(&p->threads));
  KASSERT(p->state == PROC_RUNNING || p->state == PROC_STOPPED);

  KASSERT(p->id != 0);

  // Close all open fds.
  // TODO(aoates): will need to rewrite this function to make locking work more
  // broadly.  It is _not_ correct to assume this is locked for the whole
  // function (though it is for file descriptors).
  pmutex_destructor(&p->mu);
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (p->fds[i].file >= 0) {
      int result = vfs_close(i);
      if (result) {
        klogfm(KL_PROC, WARNING, "unable to close fd %d in proc_exit(): %s\n",
               i, errorname(-result));
      }
    }
  }

  if (p->cwd) {
    vfs_put(p->cwd);
    p->cwd = 0x0;
  }

  // TODO(aoates): if this is orphaning a process group, send SIGHUP to it.

  // Note: the vm_area_t list is torn down in the parent in proc_wait, NOT here.

  // Cancel any outstanding alarms.
  proc_alarm_ms(0);

  kspin_lock(&g_proc_table_lock);
  const proc_group_t* my_pgroup = proc_group_get(p->pgroup);
  if (my_pgroup->session == p->id) {  // Controlling process/session leader.
    proc_session_t* session = proc_session_get(my_pgroup->session);
    KASSERT_DBG(p->pgroup == p->id);
    if (session->ctty != PROC_SESSION_NO_CTTY) {
      if (session->fggrp >= 0) {
        const proc_group_t* fggrp = proc_group_get(session->fggrp);
        proc_force_signal_group_locked(fggrp, SIGHUP);
      }

      tty_t* tty = tty_get(kmakedev(DEVICE_MAJOR_TTY, session->ctty));
      if (!tty) {
        klogfm(KL_PROC, DFATAL, "tty_get() in proc_exit() failed\n");
      } else {
        session->ctty = PROC_SESSION_NO_CTTY;
        tty->session = -1;
      }
    }
  }

  // Remove it from the process group list.
  proc_group_remove(proc_group_get(p->pgroup), p);
  kspin_unlock(&g_proc_table_lock);

  // Move any pending children to the root process.
  process_t* const root_process = proc_get(0);
  list_link_t* child_link = list_pop(&p->children_list);
  while (child_link) {
    process_t* const child_process = container_of(child_link, process_t,
                                                  children_link);
    KASSERT(child_process->parent == p);
    child_process->parent = root_process;
    list_push(&root_process->children_list, &child_process->children_link);
    child_link = list_pop(&p->children_list);
  }
  scheduler_wake_all(&root_process->wait_queue);

  p->state = PROC_ZOMBIE;

  // Send SIGCHLD to the parent.
  KASSERT(proc_force_signal(p->parent, SIGCHLD) == 0);

  // Wake up parent if it's wait()'ing.
  scheduler_wake_all(&p->parent->wait_queue);

  kthread_exit(0x0);
  die("unreachable");
}
