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
} signal_default_action_t;

// Table of default signal actions.
static signal_default_action_t kDefaultActions[SIGMAX + 1] = {
  SIGACT_IGNORE,  // SIGNULL
  SIGACT_TERM_AND_CORE,  // SIGABRT
  SIGACT_TERM,  // SIGALRM
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
