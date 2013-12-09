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

#include "common/kassert.h"
#include "proc/exit.h"
#include "proc/process.h"
#include "proc/user.h"
#include "proc/signal/signal_enter.h"
#include "syscall/syscalls.h"

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

int proc_force_signal(process_t* proc, int sig) {
  PUSH_AND_DISABLE_INTERRUPTS();
  int result = ksigaddset(&proc->pending_signals, sig);
  POP_INTERRUPTS();
  return result;
}

static int proc_kill_one(process_t* proc, int sig) {
  if (!proc || proc->state != PROC_RUNNING) {
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

    list_t* pgroup = proc_group_get(-pid);
    if (!pgroup || list_empty(pgroup)) {
      return -ESRCH;
    }

    int num_signalled = 0;
    for (list_link_t* link = pgroup->head; link != 0x0; link = link->next) {
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

// Dispatch a particular signal in the current process.  May not return.
static void dispatch_signal(int signum, const user_context_t* context) {
  process_t* proc = proc_current();

  const sigaction_t* action = &proc->signal_dispositions[signum];
  // TODO(aoates): support sigaction flags.

  if (action->sa_handler == SIG_IGN) {
    return;
  } else if (action->sa_handler == SIG_DFL) {
    switch (kDefaultActions[signum]) {
      case SIGACT_STOP:
      case SIGACT_CONTINUE:
        // TODO(aoates): implement STOP and CONTINUE once job control exists.
        klogf("Warning: cannot deliver stop or continue signal\n");
        return;

      case SIGACT_IGNORE:
        return;

      case SIGACT_TERM:
      case SIGACT_TERM_AND_CORE:
        // TODO(aoates): generate a core file if necessary.
        proc_exit(128 + signum);
        die("unreachable");
    }
  } else {
    KASSERT_DBG(signum != SIGKILL);
    KASSERT_DBG(signum != SIGSTOP);
    KASSERT_DBG(proc->thread == kthread_current_thread());

    // Save the old signal mask, apply the mask from the action, and mask out
    // the current signal as well.
    sigset_t old_mask = proc->thread->signal_mask;
    proc->thread->signal_mask |= action->sa_mask;
    ksigaddset(&proc->thread->signal_mask, signum);

    proc_run_user_sighandler(signum, action, &old_mask, context);
    die("unreachable");
  }
}

void proc_dispatch_pending_signals(const user_context_t* context) {
  PUSH_AND_DISABLE_INTERRUPTS();
  process_t* proc = proc_current();
  if (ksigisemptyset(&proc->pending_signals)) {
    POP_INTERRUPTS();
    return;
  }

  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    if (ksigismember(&proc->pending_signals, signum) &&
        !ksigismember(&proc->thread->signal_mask, signum)) {
      // TODO(aoates): when we support multiple threads, we'll need to switch to
      // the thread that's handling the signal.
      ksigdelset(&proc->pending_signals, signum);
      dispatch_signal(signum, context);
    }
  }

  POP_INTERRUPTS();
}

int proc_sigreturn(const sigset_t* old_mask, const user_context_t* context) {
  PUSH_AND_DISABLE_INTERRUPTS();

  // Restore the old signal mask, then process any outstanding signals.
  proc_current()->thread->signal_mask = *old_mask;
  proc_dispatch_pending_signals(context);

  POP_INTERRUPTS();

  // If there weren't any signals to be processed, restore the original context.
  user_context_apply(context);
  die("unreachable");
  return 0;
}

// If this fails, because SYS_SIGRETURN changes, the constant in
// syscall_trampoline.s must be updated to match.
_Static_assert(SYS_SIGRETURN == 21,
               "SYS_SIGRETURN must match the constant in syscall_trampoline.s");

int proc_signal_allowed(const process_t* A, const process_t* B, int signal) {
  // TODO(aoates): allow SIGCONT between processes in the same session, once we
  // have process groups and sessions.
  return (proc_is_superuser(A) ||
          A->ruid == B->ruid ||
          A->euid == B->ruid ||
          A->ruid == B->suid ||
          A->euid == B->suid);
}
