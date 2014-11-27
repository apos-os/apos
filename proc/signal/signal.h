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

#ifndef APOO_PROC_SIGNAL_SIGNAL_H
#define APOO_PROC_SIGNAL_SIGNAL_H

#include "arch/proc/user_context.h"
#include "common/errno.h"
#include "common/types.h"
#include "proc/process.h"
#include "user/include/apos/posix_signal.h"

static inline int ksigisemptyset(const sigset_t* set) {
  return (*set == 0) ? 1 : 0;
}

// Force send a signal to the given process, without any permission checks or
// the like.  Returns 0 on success, or -errno on error.
int proc_force_signal(process_t* proc, int sig);

// Send a signal to the given process, as per kill(2).  Returns 0 on success, or
// -errno on error.
int proc_kill(pid_t pid, int sig);

// Examine and/or change a signal action, as per sigaction(2).  Returns 0 on
// success, or -errno on error.
int proc_sigaction(int signum, const struct sigaction* act,
                   struct sigaction* oldact);

// Dispatch any pending signals in the current process.  If there are any
// signals that aren't blocked by the current thread's signal mask, it
// dispatches them appropriately.
//
// |context| is the user-mode context (e.g. from an interrupt or syscall being
// handled) that should be restored when all the pending signal handlers have
// returned.  A copy will be made if necessary (the caller doesn't have to
// ensure it outlives the call).
//
// Will not return if any signal handlers need to be invoked.
void proc_dispatch_pending_signals(const user_context_t* context);

// Return from a signal handling routine, via the trampoline.
int proc_sigreturn(const sigset_t* old_mask, const user_context_t* context);

// Returns 1 if process A can send the given signal to process C.
int proc_signal_allowed(const process_t* A, const process_t* B, int signal);

#endif
