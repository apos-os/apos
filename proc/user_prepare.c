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
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"

void proc_prep_user_return(user_context_t (*context_fn)(void*), void* arg,
                           syscall_context_t* syscall_ctx) {
  do {
    kthread_t me = kthread_current_thread();
    kthread_lock_proc_spin(me);
    if (ksigismember(&me->process->pending_signals, SIGCONT) ||
        ksigismember(&me->assigned_signals, SIGCONT)) {
      klogfm(KL_PROC, DEBUG, "continuing process %d", proc_current()->id);
      proc_current()->state = PROC_RUNNING;
      proc_current()->exit_status = 0x200;
      scheduler_wake_all(&proc_current()->parent->wait_queue);
      // TODO(aoates): test for this when we support multiple threads per
      // process:
      scheduler_wake_all(&proc_current()->stopped_queue);
    }
    kthread_unlock_proc_spin(me);

    if (proc_assign_pending_signals()) {
      user_context_t context = context_fn(arg);
      proc_dispatch_pending_signals(&context, syscall_ctx);
    }

    if (proc_current()->state == PROC_STOPPED) {
      scheduler_wait_on_interruptable(&proc_current()->stopped_queue, -1);
    }
  } while (proc_current()->state == PROC_STOPPED);

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
