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
#include "proc/kthread-internal.h"
#include "proc/pmutex.h"
#include "proc/process-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "vfs/vfs.h"
#include "vfs/vfs_internal.h"

void proc_exit(int status) {
  process_t* const p = proc_current();
  kthread_t thread = kthread_current_thread();
  KASSERT(thread->process == p);

  if (p->id == 0) {
    die("Cannot exit() the root thread");
  }

  kspin_lock(&p->spin_mu);
  // Note: another thread might be simultaneously calling exit() and overwrite
  // this before the exit actually happens....that's fine.
  p->exit_status = status;

  // Prevent any new threads from being created.  In the last-thread-exits
  // scenario where proc_exit() isn't called, this is unnecessary because the
  // only thread that could be creating new threads is itself exiting.
  p->exiting = true;

  // Terminate all threads in the process, then exit this one (which will clean
  // up the process if it's the last one running).
  KASSERT(p->state == PROC_RUNNING || p->state == PROC_STOPPED);
  KASSERT_DBG(list_link_on_list(&p->threads, &thread->proc_threads_link));
  FOR_EACH_LIST(iter_link, &p->threads) {
    kthread_data_t* thread_iter =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    if (thread_iter == thread) continue;

    proc_force_signal_on_thread_locked(p, thread_iter, SIGAPOSTKILL);
  }
  kspin_unlock(&p->spin_mu);

  proc_thread_exit(NULL);
}

void proc_finish_exit(void) {
  process_t* const p = proc_current();
  KASSERT(p->id != 0);

  // Phase 1: do things that require other locks (signalling) and
  // re-parent children, but leave the process in a valid and consistent state.

  // First, signal our process group if necessary.
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

  // TODO(aoates): if this is orphaning a process group, send SIGHUP to it.
  // Note: actual process group removal will happen in wait().
  kspin_unlock(&g_proc_table_lock);

  // Move any pending children to the root process.  Always lock in root ->
  // parent -> child order.
  process_t* const root_process = proc_get(0);
  pmutex_lock(&root_process->mu);
  pmutex_lock(&p->mu);
  list_link_t* child_link = list_pop(&p->children_list);
  while (child_link) {
    process_t* const child_process = container_of(child_link, process_t,
                                                  children_link);
    pmutex_lock(&child_process->mu);
    KASSERT(child_process->parent == p);
    child_process->parent = root_process;
    list_push(&root_process->children_list, &child_process->children_link);
    pmutex_unlock(&child_process->mu);
    child_link = list_pop(&p->children_list);
  }
  scheduler_wake_all(&root_process->wait_queue);
  pmutex_unlock(&p->mu);
  pmutex_unlock(&root_process->mu);

  // Phase 2: tearing down the process itself (part 1).  At this point, our
  // process is still in a consistent state, but has no children or other
  // references to clean up.

  // Start with state protected only by the mutex.
  pmutex_lock(&p->mu);

  // Close all open fds.
  for (int i = 0; i < PROC_MAX_FDS; ++i) {
    if (p->fds[i].file >= 0) {
      int result = vfs_close_locked(i);
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

  // Note: the vm_area_t list is torn down in the parent in proc_wait, NOT here.

  // Now clean up state protected by the spinlock.
  kspin_lock(&p->spin_mu);
  KASSERT(p->state == PROC_RUNNING || p->state == PROC_STOPPED);

  // Cancel any outstanding alarms.
  proc_alarm_cancel(p);

  // We must be the only thread left.  Clean up the reference, just in case.
  kthread_t me = kthread_current_thread();
  KASSERT(p->threads.head == p->threads.tail);
  KASSERT(p->threads.head == &me->proc_threads_link);
  list_pop(&p->threads);
  me->process = NULL;

  p->state = PROC_ZOMBIE;

  kspin_unlock(&p->spin_mu);
  pmutex_unlock(&p->mu);

  // Phase 3: we must now signal our parent. This requires some locking fun.
  process_t* parent = proc_get_and_lock_parent(p);
  pmutex_assert_is_held(&parent->mu);

  // Send SIGCHLD to the parent.
  KASSERT(proc_force_signal(parent, SIGCHLD) == 0);

  // Wake up parent if it's wait()'ing.
  scheduler_wake_all(&parent->wait_queue);

  pmutex_unlock(&p->mu);
  pmutex_unlock(&parent->mu);
  proc_put(parent);

  kthread_exit(0x0);
  die("unreachable");
}
