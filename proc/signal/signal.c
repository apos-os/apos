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

#include "proc/signal/signal.h"

#include "arch/proc/signal/signal_enter.h"
#include "arch/syscall/context.h"
#include "common/kassert.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/exit.h"
#include "proc/group.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/user.h"
#include "proc/user_prepare.h"
#include "user/include/apos/syscalls.h"

// Possible default actions for signals.
typedef enum {
  SIGACT_TERM,
  SIGACT_TERM_AND_CORE,
  SIGACT_TERM_THREAD,
  SIGACT_IGNORE,
  SIGACT_STOP,
  SIGACT_CONTINUE,
} signal_default_action_t;

// Table of default signal actions.
static signal_default_action_t kDefaultActions[APOS_SIGMAX + 1] = {
  SIGACT_IGNORE,        // SIGNULL
  SIGACT_TERM_AND_CORE, // SIGABRT
  SIGACT_TERM,          // SIGALRM
  SIGACT_TERM_AND_CORE, // SIGBUS
  SIGACT_IGNORE,        // SIGCHLD
  SIGACT_CONTINUE,      // SIGCONT
  SIGACT_TERM_AND_CORE, // SIGFPE
  SIGACT_TERM,          // SIGHUP
  SIGACT_TERM_AND_CORE, // SIGILL
  SIGACT_TERM,          // SIGINT
  SIGACT_TERM,          // SIGKILL
  SIGACT_TERM,          // SIGPIPE
  SIGACT_TERM_AND_CORE, // SIGQUIT
  SIGACT_TERM_AND_CORE, // SIGSEGV
  SIGACT_STOP,          // SIGSTOP
  SIGACT_TERM,          // SIGTERM
  SIGACT_STOP,          // SIGTSTP
  SIGACT_STOP,          // SIGTTIN
  SIGACT_STOP,          // SIGTTOU
  SIGACT_TERM,          // SIGUSR1
  SIGACT_TERM,          // SIGUSR2
  SIGACT_TERM_AND_CORE, // SIGSYS
  SIGACT_TERM_AND_CORE, // SIGTRAP
  SIGACT_IGNORE,        // SIGURG
  SIGACT_TERM,          // SIGVTALRM
  SIGACT_TERM_AND_CORE, // SIGXCPU
  SIGACT_TERM_AND_CORE, // SIGXFSZ
  SIGACT_IGNORE,        // SIGWINCH
  SIGACT_IGNORE,        // SIGAPOSTEST
  SIGACT_TERM_THREAD,   // SIGAPOSTKILL
};

static const ksigset_t kUnblockableSignals =
    (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1)) | (1 << (SIGAPOSTKILL - 1));

ksigset_t proc_pending_signals(const process_t* proc) {
  ksigset_t set = proc->pending_signals;
  FOR_EACH_LIST(iter_link, &proc->threads) {
    const kthread_data_t* thread =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    set = ksigunionset(set, thread->assigned_signals);
  }
  return set;
}

bool proc_signal_deliverable(kthread_t thread, int signum) {
  const ksigaction_t* action = &thread->process->signal_dispositions[signum];
  if (action->sa_handler == SIG_IGN) {
    return false;
  } else if (action->sa_handler == SIG_DFL &&
             kDefaultActions[signum] == SIGACT_IGNORE) {
    return false;
  } else if (ksigismember(&thread->signal_mask, signum)) {
    return false;
  } else if (action->sa_handler != SIG_DFL &&
             thread->process->state == PROC_STOPPED) {
    return false;
  }

  return true;
}

ksigset_t proc_dispatchable_signals(void) {
  ksigset_t set;
  ksigemptyset(&set);
  kthread_t thread = kthread_current_thread();
  if (thread == KTHREAD_NO_THREAD || !thread->process) return set;

  // TODO(aoates): rather than iterating through all the signals, track the set
  // of currently-ignored signals and use that here.
  for (int signum = APOS_SIGMIN; signum <= APOS_SIGMAX; ++signum) {
    if (ksigismember(&thread->assigned_signals, signum) &&
        proc_signal_deliverable(thread, signum))
      ksigaddset(&set, signum);
  }

  return set;
}

// Force assign the given signal to the thread.  If the signal isn't masked, and
// will be delivered to the thread, try to wake it up.
static void do_assign_signal(kthread_t thread, int signum) {
  ksigaddset(&thread->assigned_signals, signum);
  if (proc_signal_deliverable(thread, signum)) {
    scheduler_interrupt_thread(thread);
  }
}

// Try to assign the given signal to a thread in the process.  Fails if it is
// masked in all threads, returning false.
static void proc_try_assign_signal(process_t* proc, int signum) {
  if (proc->state == PROC_ZOMBIE) {
    return;
  }

  KASSERT_DBG(ksigismember(&proc->pending_signals, signum));

  // Ideally this would be non-deterministic to prevent anyone from relying on
  // the signal always being assigned to the first thread without it masked.
  FOR_EACH_LIST(iter_link, &proc->threads) {
    kthread_data_t* thread =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    if (!ksigismember(&thread->signal_mask, signum)) {
      ksigdelset(&proc->pending_signals, signum);
      do_assign_signal(thread, signum);
      break;
    }
  }
}

int proc_force_signal(process_t* proc, int sig) {
  KASSERT_DBG(sig != SIGAPOSTKILL);  // Must be sent to specific thread.

  PUSH_AND_DISABLE_INTERRUPTS();
  int result = ksigaddset(&proc->pending_signals, sig);
  proc_try_assign_signal(proc, sig);
  POP_INTERRUPTS();

  // Wake up a stopped victim at random to handle the SIGCONT (it will update
  // the process's state, wake up the rest of the threads, etc).
  if (sig == SIGCONT) {
    scheduler_wake_one(&proc->stopped_queue);
  }

  return result;
}

int proc_force_signal_group(kpid_t pgid, int sig) {
  PUSH_AND_DISABLE_INTERRUPTS();
  proc_group_t* pgroup = proc_group_get(pgid);
  if (!pgroup) {
    klogfm(KL_PROC, DFATAL, "invalid pgid in proc_force_signal_group(): %d\n",
           pgid);
    POP_INTERRUPTS();
    return -EINVAL;
  }

  int result = 0;
  for (list_link_t* link = pgroup->procs.head; link != 0x0; link = link->next) {
    result =
        proc_force_signal(container_of(link, process_t, pgroup_link), sig);
    if (result) break;
  }

  POP_INTERRUPTS();
  return result;
}

int proc_force_signal_on_thread(process_t* proc, kthread_t thread, int sig) {
  // This isn't very interesting until we have multiple threads in a process.
  KASSERT(thread->process == proc);
  KASSERT_DBG(list_link_on_list(&proc->threads, &thread->proc_threads_link));
  PUSH_AND_DISABLE_INTERRUPTS();
  do_assign_signal(thread, sig);
  POP_INTERRUPTS();
  return 0;
}

static int proc_kill_one(process_t* proc, int sig) {
  if (!proc || (proc->state != PROC_RUNNING && proc->state != PROC_STOPPED &&
                proc->state != PROC_ZOMBIE)) {
    return -ESRCH;
  }

  if (!proc_signal_allowed(proc_current(), proc, sig)) {
    return -EPERM;
  }

  if (sig == APOS_SIGNULL) {
    return 0;
  }

  return proc_force_signal(proc, sig);
}

int proc_kill(kpid_t pid, int sig) {
  if (sig < APOS_SIGNULL || sig > APOS_SIGMAX) {
    return -EINVAL;
  }

  if (pid == -1) {
    for (kpid_t pid = 2; pid < PROC_MAX_PROCS; pid++) {
      proc_kill_one(proc_get(pid), sig);
    }
    return 0;
  } else if (pid <= 0) {
    if (pid == 0) pid = -proc_current()->pgroup;

    const proc_group_t* pgroup = proc_group_get(-pid);
    if (!pgroup || list_empty(&pgroup->procs)) {
      return -ESRCH;
    }

    int num_signalled = 0;
    for (list_link_t* link = pgroup->procs.head; link != 0x0;
         link = link->next) {
      int result =
          proc_kill_one(container_of(link, process_t, pgroup_link), sig);
      KASSERT_DBG(result == 0 || result == -EPERM);
      if (result == 0) num_signalled++;
    }
    return (num_signalled > 0) ? 0 : -EPERM;
  } else {
    process_t* proc = proc_get(pid);
    return proc_kill_one(proc, sig);
  }
}

int proc_kill_thread(kthread_t thread, int sig) {
  KASSERT(thread->process);

  if (sig < APOS_SIGNULL || sig > APOS_SIGMAX) {
    return -EINVAL;
  }

  if (!proc_signal_allowed(proc_current(), thread->process, sig)) {
    return -EPERM;
  }

  if (sig == APOS_SIGNULL) {
    return 0;
  }

  return proc_force_signal_on_thread(thread->process, thread, sig);
}

int proc_sigaction(int signum, const struct ksigaction* act,
                   struct ksigaction* oldact) {
  if (signum < APOS_SIGMIN || signum > APOS_SIGMAX) {
    return -EINVAL;
  }

  if (ksigismember(&kUnblockableSignals, signum) && act != 0x0) {
    return -EINVAL;
  }

  if (oldact) {
    *oldact = proc_current()->signal_dispositions[signum];
  }

  if (act) {
    PUSH_AND_DISABLE_INTERRUPTS();
    proc_current()->signal_dispositions[signum] = *act;
    POP_INTERRUPTS();
  }

  return 0;
}

int proc_sigprocmask(int how, const ksigset_t* restrict set,
                     ksigset_t* restrict oset) {
  if (oset) {
    *oset = kthread_current_thread()->signal_mask;
  }

  ksigset_t new_mask = kthread_current_thread()->signal_mask;
  if (set) {
    switch (how) {
      case SIG_BLOCK:
        new_mask |= *set;
        break;

      case SIG_UNBLOCK:
        new_mask &= ~(*set);
        break;

      case SIG_SETMASK:
        new_mask = *set;
        break;

      default:
        return -EINVAL;
    }
  }
  new_mask = ksigsubtractset(new_mask, kUnblockableSignals);
  kthread_current_thread()->signal_mask = new_mask;
  return 0;
}

int proc_sigpending(ksigset_t* set) {
  process_t* proc = proc_current();
  kthread_data_t* thread = kthread_current_thread();
  KASSERT(thread->process == proc);
  KASSERT_DBG(list_link_on_list(&proc->threads, &thread->proc_threads_link));
  *set = proc->pending_signals |
      (thread->assigned_signals & thread->signal_mask);
  return 0;
}

int proc_sigsuspend(const ksigset_t* sigmask) {
  ksigset_t old_mask;
  int result = proc_sigprocmask(SIG_SETMASK, sigmask, &old_mask);
  KASSERT_DBG(result == 0);
  proc_assign_pending_signals();

  kthread_queue_t queue;
  kthread_queue_init(&queue);
  result = scheduler_wait_on_interruptable(&queue, -1);
  KASSERT_DBG(result == SWAIT_INTERRUPTED);

  // We can't restore the original mask now, since that would prevent
  // dispatching the signals we just woke up from.  So we save it to restore
  // just before returning to userspace.
  kthread_current_thread()->syscall_ctx.restore_mask = old_mask;
  kthread_current_thread()->syscall_ctx.flags |= SCCTX_RESTORE_MASK;

  return -EINTR;
}

int proc_sigwait(const ksigset_t* set, int* sig_out) {
  // All requested signals must already be blocked.
  kthread_t thread = kthread_current_thread();
  if ((*set & thread->signal_mask) != *set) {
    return -EINVAL;
  }

  ksigset_t old_mask;
  int result = proc_sigprocmask(SIG_UNBLOCK, set, &old_mask);
  KASSERT_DBG(result == 0);
  proc_assign_pending_signals();

  kthread_queue_t queue;
  kthread_queue_init(&queue);
  result = scheduler_wait_on_interruptable(&queue, -1);
  KASSERT_DBG(result == SWAIT_INTERRUPTED);

  // Find a signal to pass back.
  ksigset_t waitable_signals = *set & thread->assigned_signals;
  result = -EINTR;
  if (!ksigisemptyset(waitable_signals)) {
    for (int signum = APOS_SIGMIN; signum <= APOS_SIGMAX; ++signum) {
      // We use proc_signal_deliverable() as well as checking the mask to ignore
      // signals that are ignored.
      if (ksigismember(&waitable_signals, signum) &&
          proc_signal_deliverable(thread, signum)) {
        ksigdelset(&thread->assigned_signals, signum);
        *sig_out = signum;
        result = 0;
        break;
      }
    }
  }

  KASSERT(0 == proc_sigprocmask(SIG_SETMASK, &old_mask, NULL));
  return result;
}

void proc_suppress_signal(process_t* proc, int sig) {
  ksigdelset(&proc->pending_signals, sig);
  FOR_EACH_LIST(iter_link, &proc->threads) {
    kthread_data_t* thread =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    ksigdelset(&thread->assigned_signals, sig);
  }
}

// Dispatch a particular signal in the current process.  May not return.
// Returns true if the signal was dispatched (which includes being ignored), or
// false if it couldn't be (because the process is stopped).
static bool dispatch_signal(int signum, const user_context_t* context,
                            syscall_context_t* syscall_ctx) {
  process_t* proc = proc_current();
  KASSERT_DBG(proc->state == PROC_RUNNING || proc->state == PROC_STOPPED);

  const ksigaction_t* action = &proc->signal_dispositions[signum];
  // TODO(aoates): support sigaction flags.

  if (action->sa_handler == SIG_IGN) {
    KASSERT_DBG(!proc_signal_deliverable(kthread_current_thread(), signum));
    return true;
  } else if (action->sa_handler == SIG_DFL) {
    switch (kDefaultActions[signum]) {
      case SIGACT_STOP:
        KASSERT_DBG(proc_signal_deliverable(kthread_current_thread(), signum));
        klogfm(KL_PROC, DEBUG, "stopping process %d", proc->id);
        proc->state = PROC_STOPPED;
        proc->exit_status = 0x100 | signum;
        scheduler_wake_all(&proc->parent->wait_queue);
        break;

      case SIGACT_CONTINUE:
        KASSERT_DBG(proc_signal_deliverable(kthread_current_thread(), signum));
        // We should have already been continued before calling this.
        KASSERT_DBG(proc->state == PROC_RUNNING);
        break;

      case SIGACT_IGNORE:
        KASSERT_DBG(!proc_signal_deliverable(kthread_current_thread(), signum));
        return true;

      case SIGACT_TERM:
      case SIGACT_TERM_AND_CORE:
        // TODO(aoates): generate a core file if necessary.
        KASSERT_DBG(proc_signal_deliverable(kthread_current_thread(), signum));
        proc_exit(128 + signum);
        die("unreachable");

      case SIGACT_TERM_THREAD:
        proc_thread_exit(NULL);
        die("unreachable");
    }
  } else {
    KASSERT_DBG(signum != SIGKILL);
    KASSERT_DBG(signum != SIGSTOP);
    KASSERT_DBG(signum != SIGAPOSTKILL);
    kthread_data_t* thread = kthread_current_thread();
    KASSERT(thread->process == proc);
    KASSERT_DBG(list_link_on_list(&proc->threads, &thread->proc_threads_link));

    if (proc->state == PROC_STOPPED)
      return false;

    // Save the old signal mask, apply the mask from the action, and mask out
    // the current signal as well.
    KASSERT_DBG(proc_signal_deliverable(thread, signum));
    ksigset_t old_mask = thread->signal_mask;
    thread->signal_mask |= action->sa_mask;
    if (!(action->sa_flags & SA_NODEFER))
      ksigaddset(&thread->signal_mask, signum);

    if (syscall_ctx && !(action->sa_flags & SA_RESTART))
      syscall_ctx->flags &= ~SCCTX_RESTARTABLE;

    proc_run_user_sighandler(signum, action, &old_mask, context, syscall_ctx);
    die("unreachable");
  }

  return true;
}

// Assign any pending signals in the process to a thread that can handle them,
// if any.
static void signal_assign_pending(process_t* proc) {
  for (int signum = APOS_SIGMIN; signum <= APOS_SIGMAX; ++signum) {
    if (ksigismember(&proc->pending_signals, signum)) {
      proc_try_assign_signal(proc, signum);
    }
  }
}

int proc_assign_pending_signals(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_data_t* thread = kthread_current_thread();
  KASSERT(thread->process == proc_current());
  KASSERT_DBG(
      list_link_on_list(&proc_current()->threads, &thread->proc_threads_link));

  signal_assign_pending(proc_current());
  int result = !ksigisemptyset(thread->assigned_signals);

  POP_INTERRUPTS();
  return result;
}

void proc_dispatch_pending_signals(const user_context_t* context,
                                   syscall_context_t* syscall_ctx) {
  PUSH_AND_DISABLE_INTERRUPTS();

  const kthread_t thread = kthread_current_thread();
  KASSERT_DBG(thread->process == proc_current());
  KASSERT_DBG(
      list_link_on_list(&proc_current()->threads, &thread->proc_threads_link));

  if (ksigisemptyset(thread->assigned_signals)) {
    POP_INTERRUPTS();
    return;
  }

  for (int signum = APOS_SIGMIN; signum <= APOS_SIGMAX; ++signum) {
    // We need to check the thread's signal mask again, since there may be
    // signals that are assigned to the thread even though they're masked (e.g.
    // one sent with pthread_kill()).
    if (ksigismember(&thread->assigned_signals, signum) &&
        !ksigismember(&thread->signal_mask, signum)) {
      ksigdelset(&thread->assigned_signals, signum);
      if (!dispatch_signal(signum, context, syscall_ctx)) {
        // Re-enqueue the signal for delivery later.
        ksigaddset(&thread->assigned_signals, signum);
      }
    }
  }

  POP_INTERRUPTS();
}

static user_context_t get_user_context(void* arg) {
  return *(user_context_t*)arg;
}

int proc_sigreturn(const ksigset_t* old_mask_ptr,
                   const user_context_t* context_ptr,
                   const syscall_context_t* syscall_ctx_ptr) {
  const ksigset_t old_mask = *old_mask_ptr;
  user_context_t context = *context_ptr;
  syscall_context_t syscall_ctx;
  if (syscall_ctx_ptr) syscall_ctx = *syscall_ctx_ptr;
  kfree((void*)old_mask_ptr);
  kfree((void*)context_ptr);
  if (syscall_ctx_ptr) kfree((void*)syscall_ctx_ptr);

  PUSH_AND_DISABLE_INTERRUPTS();

  // Restore the old signal mask, then process any outstanding signals.
  kthread_t thread = kthread_current_thread();
  KASSERT_DBG(thread->process == proc_current());
  KASSERT_DBG(
      list_link_on_list(&proc_current()->threads, &thread->proc_threads_link));
  thread->signal_mask = old_mask;

  // This catches, for example, signals raised in the signal handler that were
  // blocked.
  proc_prep_user_return(&get_user_context, (void*)&context,
                        syscall_ctx_ptr ? &syscall_ctx : NULL);

  POP_INTERRUPTS();

  // TODO(aoates): ideally we'd do this in proc_prep_user_return().
  if (syscall_ctx_ptr && (syscall_ctx.flags & SCCTX_RESTARTABLE) &&
      syscall_get_result(&context) == -EINTR) {
    syscall_set_result(&context, -EINTR_RESTART);
  }

  // If there weren't any signals to be processed, restore the original context.
  user_context_apply(&context);
  die("unreachable");
  return 0;
}

// If this fails, because SYS_SIGRETURN changes, the constant in
// syscall_trampoline.s must be updated to match.
_Static_assert(SYS_SIGRETURN == 21,
               "SYS_SIGRETURN must match the constant in syscall_trampoline.s");

int proc_signal_allowed(const process_t* A, const process_t* B, int signal) {
  // SIGAPOSTKILL is never allowed to be sent (except internally, to a specific
  // thread, which bypasses this check).
  if (signal == SIGAPOSTKILL) return 0;
  return (proc_is_superuser(A) ||
          A->ruid == B->ruid ||
          A->euid == B->ruid ||
          A->ruid == B->suid ||
          A->euid == B->suid ||
          (proc_group_get(A->pgroup)->session ==
           proc_group_get(B->pgroup)->session &&
           signal == SIGCONT));
}
