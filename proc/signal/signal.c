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
#include "common/kassert.h"
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
  SIGACT_IGNORE,
  SIGACT_STOP,
  SIGACT_CONTINUE,
} signal_default_action_t;

// Table of default signal actions.
static signal_default_action_t kDefaultActions[SIGMAX + 1] = {
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
};

sigset_t proc_pending_signals(const process_t* proc) {
  return ksigunionset(&proc->pending_signals, &proc->thread->assigned_signals);
}

bool proc_signal_deliverable(kthread_t thread, int signum) {
  const sigaction_t* action = &thread->process->signal_dispositions[signum];
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

sigset_t proc_dispatchable_signals(void) {
  sigset_t set;
  ksigemptyset(&set);
  kthread_t thread = kthread_current_thread();
  if (thread == KTHREAD_NO_THREAD || !thread->process) return set;

  // TODO(aoates): rather than iterating through all the signals, track the set
  // of currently-ignored signals and use that here.
  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
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
  const kthread_t thread = proc->thread;

  KASSERT_DBG(ksigismember(&proc->pending_signals, signum));
  if (!ksigismember(&thread->signal_mask, signum)) {
    ksigdelset(&proc->pending_signals, signum);
    do_assign_signal(thread, signum);
  }
}

int proc_force_signal(process_t* proc, int sig) {
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

int proc_force_signal_group(pid_t pgid, int sig) {
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
  KASSERT_DBG(thread == proc->thread);
  PUSH_AND_DISABLE_INTERRUPTS();
  do_assign_signal(thread, sig);
  POP_INTERRUPTS();
  return 0;
}

static int proc_kill_one(process_t* proc, int sig) {
  if (!proc || (proc->state != PROC_RUNNING && proc->state != PROC_STOPPED)) {
    return -ESRCH;
  }

  if (!proc_signal_allowed(proc_current(), proc, sig)) {
    return -EPERM;
  }

  if (sig == SIGNULL) {
    return 0;
  }

  return proc_force_signal(proc, sig);
}

int proc_kill(pid_t pid, int sig) {
  if (sig < SIGNULL || sig > SIGMAX) {
    return -EINVAL;
  }

  if (pid == -1) {
    for (pid_t pid = 2; pid < PROC_MAX_PROCS; pid++) {
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

int proc_sigaction(int signum, const struct sigaction* act,
                   struct sigaction* oldact) {
  if (signum < SIGMIN || signum > SIGMAX) {
    return -EINVAL;
  }

  if ((signum == SIGKILL || signum == SIGSTOP) && act != 0x0) {
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

int proc_sigprocmask(int how, const sigset_t* restrict set,
                     sigset_t* restrict oset) {
  if (oset) {
    *oset = kthread_current_thread()->signal_mask;
  }

  sigset_t new_mask = kthread_current_thread()->signal_mask;
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
  ksigdelset(&new_mask, SIGKILL);
  ksigdelset(&new_mask, SIGSTOP);
  kthread_current_thread()->signal_mask = new_mask;
  return 0;
}

int proc_sigpending(sigset_t* set) {
  process_t* proc = proc_current();
  kthread_t thread = proc->thread;
  *set = proc->pending_signals |
      (thread->assigned_signals & thread->signal_mask);
  return 0;
}

int proc_sigsuspend(const sigset_t* sigmask) {
  sigset_t old_mask;
  int result = proc_sigprocmask(SIG_SETMASK, sigmask, &old_mask);
  KASSERT_DBG(result == 0);

  kthread_queue_t queue;
  kthread_queue_init(&queue);
  result = scheduler_wait_on_interruptable(&queue);
  KASSERT_DBG(result);

  result = proc_sigprocmask(SIG_SETMASK, &old_mask, NULL);
  KASSERT_DBG(result == 0);

  return -EINTR;
}

void proc_suppress_signal(process_t* proc, int sig) {
  ksigdelset(&proc->pending_signals, sig);
  ksigdelset(&proc->thread->assigned_signals, sig);
}

// Dispatch a particular signal in the current process.  May not return.
// Returns true if the signal was dispatched (which includes being ignored), or
// false if it couldn't be (because the process is stopped).
static bool dispatch_signal(int signum, const user_context_t* context) {
  process_t* proc = proc_current();
  KASSERT_DBG(proc->state == PROC_RUNNING || proc->state == PROC_STOPPED);

  const sigaction_t* action = &proc->signal_dispositions[signum];
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
    }
  } else {
    KASSERT_DBG(signum != SIGKILL);
    KASSERT_DBG(signum != SIGSTOP);
    KASSERT_DBG(proc->thread == kthread_current_thread());

    if (proc->state == PROC_STOPPED)
      return false;

    // Save the old signal mask, apply the mask from the action, and mask out
    // the current signal as well.
    KASSERT_DBG(proc_signal_deliverable(kthread_current_thread(), signum));
    sigset_t old_mask = proc->thread->signal_mask;
    proc->thread->signal_mask |= action->sa_mask;
    ksigaddset(&proc->thread->signal_mask, signum);

    proc_run_user_sighandler(signum, action, &old_mask, context);
    die("unreachable");
  }

  return true;
}

// Assign any pending signals in the process to a thread that can handle them,
// if any.  Since we currently only have one thread per process, this is pretty
// straightforward.
static void signal_assign_pending(process_t* proc) {
  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    if (ksigismember(&proc->pending_signals, signum)) {
      proc_try_assign_signal(proc, signum);
    }
  }
}

int proc_assign_pending_signals(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT_DBG(kthread_current_thread()->process == proc_current());
  KASSERT_DBG(proc_current()->thread == kthread_current_thread());

  signal_assign_pending(proc_current());
  int result = !ksigisemptyset(&kthread_current_thread()->assigned_signals);

  POP_INTERRUPTS();
  return result;
}

void proc_dispatch_pending_signals(const user_context_t* context) {
  PUSH_AND_DISABLE_INTERRUPTS();

  const kthread_t thread = proc_current()->thread;
  KASSERT_DBG(thread == kthread_current_thread());

  if (ksigisemptyset(&thread->assigned_signals)) {
    POP_INTERRUPTS();
    return;
  }

  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    // We need to check the thread's signal mask again, since there may be
    // signals that are assigned to the thread even though they're masked (e.g.
    // one sent with pthread_kill()).
    if (ksigismember(&thread->assigned_signals, signum) &&
        !ksigismember(&thread->signal_mask, signum)) {
      ksigdelset(&thread->assigned_signals, signum);
      if (!dispatch_signal(signum, context)) {
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

int proc_sigreturn(const sigset_t* old_mask_ptr,
                   const user_context_t* context_ptr) {
  const sigset_t old_mask = *old_mask_ptr;
  const user_context_t context = *context_ptr;
  kfree((void*)old_mask_ptr);
  kfree((void*)context_ptr);

  PUSH_AND_DISABLE_INTERRUPTS();

  // Restore the old signal mask, then process any outstanding signals.
  proc_current()->thread->signal_mask = old_mask;

  // This catches, for example, signals raised in the signal handler that were
  // blocked.
  proc_prep_user_return(&get_user_context, (void*)&context);

  POP_INTERRUPTS();

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
  return (proc_is_superuser(A) ||
          A->ruid == B->ruid ||
          A->euid == B->ruid ||
          A->ruid == B->suid ||
          A->euid == B->suid ||
          (proc_group_get(A->pgroup)->session ==
           proc_group_get(B->pgroup)->session &&
           signal == SIGCONT));
}
