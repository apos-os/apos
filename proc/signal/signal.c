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

int proc_kill(pid_t pid, int sig) {
  if (pid == 0) {
    return -EINVAL;
  }

  process_t* proc = proc_get(pid);
  if (!proc || proc->state != PROC_RUNNING) {
    return -EINVAL;
  }

  if (sig == SIGNULL) {
    return 0;
  }

  return ksigaddset(&proc->pending_signals, sig);
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

  // TODO(aoates): should we check for bad flags?

  if (act) {
    proc_current()->signal_dispositions[signum] = *act;
  }

  return 0;
}

// Dispatch a particular signal in the current process.  May not return.
static void dispatch_signal(int signum, user_context_t context) {
  process_t* proc = proc_current();

  const sigaction_t* action = &proc->signal_dispositions[signum];
  // TODO(aoates): support sigaction flags.
  KASSERT_DBG(action->sa_flags == 0);
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
    // TODO(aoates): support custom signal handlers.
    die("cannot dispatch to custom signal handler");
  }
}

void proc_dispatch_pending_signals(user_context_t context) {
  process_t* proc = proc_current();
  if (ksigisemptyset(&proc->pending_signals)) {
    return;
  }

  for (int signum = SIGMIN; signum <= SIGMAX; ++signum) {
    if (ksigismember(&proc->pending_signals, signum) &&
        !ksigismember(&proc->thread->signal_mask, signum)) {
      ksigdelset(&proc->pending_signals, signum);
      dispatch_signal(signum, context);
    }
  }

}
