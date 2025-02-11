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

// Signals go through three phases.
// 1) generated --- when the signal is first generated.  When generated, a
// signal is either specific to a particular thread (e.g. SIGFPE or a signal
// sent with pthread_kill()), or for the entire process.
//
// 2) assigned --- the signal is assigned to a particular thread for handling.
// If the generated signal is specific to a particular thread, it is assigned to
// that thread directly.  Otherwise, it will be assigned to any thread that
// doesn't have it masked.
//
// 3) dispatched --- the signal is dispatched to the handling thread.  This
// happens when returning from an interrupt or syscall.

#include "arch/proc/user_context.h"
#include "common/types.h"
#include "proc/process.h"
#include "syscall/context.h"
#include "user/include/apos/posix_signal.h"

static inline int ksigisemptyset(ksigset_t set) {
  return (set == 0) ? 1 : 0;
}

static inline ksigset_t ksigunionset(ksigset_t A, ksigset_t B) {
  return A | B;
}

static inline ksigset_t ksigsubtractset(ksigset_t A, ksigset_t B) {
  return A & ~B;
}

// Returns all the pending or assigned signals on the given process.
ksigset_t proc_pending_signals(const process_t* proc);

// Returns all the signals that are assigned, unmasked, and not ignored in the
// current thread (i.e., ones that will be dispatched next).
ksigset_t proc_dispatchable_signals(void);

// Returns true if the given signal can be delivered to the thread (i.e. it's
// not blocked or ignored [explicitly or by default]).
bool proc_signal_deliverable(kthread_t thread, int signum);

// Force send a signal to the given process, without any permission checks or
// the like.  Returns 0 on success, or -errno on error.
int proc_force_signal(process_t* proc, int sig);

// As above, but sends a signal to every process in the given group.
int proc_force_signal_group(kpid_t pgid, int sig);

// As above, but forces the signal to be handled on the given thread.  Returns 0
// on success, or -errno on error.
int proc_force_signal_on_thread(process_t* proc, kthread_t thread, int sig);

// Send a signal to the given process, as per kill(2).  Returns 0 on success, or
// -errno on error.
int proc_kill(kpid_t pid, int sig);
int proc_kill_thread(kthread_t thread, int sig);

// Examine and/or change a signal action, as per sigaction(2).  Returns 0 on
// success, or -errno on error.
int proc_sigaction(int signum, const struct ksigaction* act,
                   struct ksigaction* oldact);

// Adjust the current thread's signal mask.  Returns 0 on success, or -error.
int proc_sigprocmask(int how, const ksigset_t* restrict set,
                     ksigset_t* restrict oset);

// Return the current set of pending signals in the calling thread.
int proc_sigpending(ksigset_t* set);

// Temporarily set the current thread's signal mask, then block until a signal
// is delivered.
int proc_sigsuspend(const ksigset_t* sigmask);

// Waits for one of the given signals to be delivered, then returns.
int proc_sigwait(const ksigset_t* set, int* sig);

// Cancel/suppress the given signal in the given process and its threads.
// Useful in tests.
void proc_suppress_signal(process_t* proc, int sig);

// Attempts to assign any pending signals in the current process to the current
// thread.  It returns 1 if the thread has any assigned signals (newly assigned
// or not).
//
// Call this before proc_dispatch_pending_signals(), using its return value to
// determine if you need to generate a user_context_t.
//
// NOTE: proc_dispatch_pending_signals() may not dispatch any signals, even if
// proc_assign_pending_signals() returns 1, for example if the signals are
// masked.
int proc_assign_pending_signals(void);

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
void proc_dispatch_pending_signals(const user_context_t* context,
                                   syscall_context_t* syscall_ctx);

// Return from a signal handling routine, via the trampoline.
// Frees old_mask and context.
int proc_sigreturn(const ksigset_t* old_mask, const user_context_t* context,
                   const syscall_context_t* syscall_ctx);

// Returns 1 if process A can send the given signal to process C.
int proc_signal_allowed(const process_t* A, const process_t* B, int signal);

#endif
