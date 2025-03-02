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

#include "proc/user_prepare.h"

#include "common/kassert.h"
#include "common/klog.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"

void proc_prep_user_return(user_context_t (*context_fn)(void*), void* arg,
                           syscall_context_t* syscall_ctx) {
  kthread_t me = kthread_current_thread();
  kthread_lock_proc_spin(me);
  do {
    if (ksigismember(&me->process->pending_signals, SIGCONT) ||
        ksigismember(&me->assigned_signals, SIGCONT)) {
      klogfm(KL_PROC, DEBUG, "continuing process %d", proc_current()->id);
      proc_current()->state = PROC_RUNNING;
      proc_current()->exit_status = 0x200;

      // TODO(aoates): test for this when we support multiple threads per
      // process:
      scheduler_wake_all(&proc_current()->stopped_queue);
      kthread_unlock_proc_spin(me);

      // We now need to signal our parent who might be waiting for us to
      // continue.  We must relock.  It's possible a parent process thread
      // already came through and collected our continued status, in which case
      // this is harmlessly spurious.
      // TODO(aoates): would be nice to have a test for that race.
      process_t* parent = proc_get_and_lock_parent(me->process);
      pmutex_assert_is_held(&parent->mu);
      scheduler_wake_all(&parent->wait_queue);
      pmutex_unlock(&me->process->mu);
      pmutex_unlock(&parent->mu);
      proc_put(parent);
    } else {
      // Unlock to assign signals.
      kthread_unlock_proc_spin(me);
    }

    if (proc_assign_pending_signals()) {
      user_context_t context = context_fn(arg);
      proc_dispatch_pending_signals(&context, syscall_ctx);
    }
    // TODO(smp): this is racy --- a signal could come in just before we re-lock
    // here, and due to SWAIT_NO_SIGNAL_CHECK, we'd miss it.  Fix and test.
    kthread_lock_proc_spin(me);

    if (me->process->state == PROC_STOPPED) {
      // We don't want scheduler_wait() to re-check signals (which would require
      // re-taking me->process->spin_mu).
      scheduler_wait(&me->process->stopped_queue, SWAIT_NO_SIGNAL_CHECK, -1,
                     NULL, &me->process->spin_mu);
    }
  } while (proc_current()->state == PROC_STOPPED);
  // TODO(SMP): need to close this race condition --- another thread could
  // come in and stop us right after we unlock the spinlock.
  kthread_unlock_proc_spin(me);

  if (syscall_ctx) {
    KASSERT_DBG(
        (syscall_ctx->flags & ~SCCTX_RESTORE_MASK & ~SCCTX_RESTARTABLE) == 0);
    if (syscall_ctx->flags & SCCTX_RESTORE_MASK) {
      int result =
          proc_sigprocmask(SIG_SETMASK, &syscall_ctx->restore_mask, NULL);
      KASSERT_DBG(result == 0);
    }
  }
}
