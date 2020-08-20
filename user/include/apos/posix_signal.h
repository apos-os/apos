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

// Contains the POSIX-required definitions and constants for <signal.h>.  To be
// shared between kernel and user code.
#ifndef APOO_USER_POSIX_SIGNAL_H
#define APOO_USER_POSIX_SIGNAL_H

#include <stdint.h>

#if __APOS_BUILDING_IN_TREE__
#  include "user/include/apos/errors.h"
#else
#  include <apos/errors.h>
#endif

typedef uint32_t ksigset_t;
typedef void (*ksighandler_t)(int);

// Signal numbers.
#define SIGNULL 0
#define SIGMIN 1

#define SIGABRT   1   // Process abort signal.
#define SIGALRM   2   // Alarm clock.
#define SIGBUS    3   // Access to an undefined portion of a memory object.
#define SIGCHLD   4   // Child process terminated, stopped, or continued.
#define SIGCONT   5   // Continue executing, if stopped.
#define SIGFPE    6   // Erroneous arithmetic operation.
#define SIGHUP    7   // Hangup.
#define SIGILL    8   // Illegal instruction.
#define SIGINT    9   // Terminal interrupt signal.
#define SIGKILL   10  // Kill (cannot be caught or ignored).
#define SIGPIPE   11  // Write on a pipe with no one to read it.
#define SIGQUIT   12  // Terminal quit signal.
#define SIGSEGV   13  // Invalid memory reference.
#define SIGSTOP   14  // Stop executing (cannot be caught or ignored).
#define SIGTERM   15  // Termination signal.
#define SIGTSTP   16  // Terminal stop signal.
#define SIGTTIN   17  // Background process attempting read.
#define SIGTTOU   18  // Background process attempting write.
#define SIGUSR1   19  // User-defined signal 1.
#define SIGUSR2   20  // User-defined signal 2.
#define SIGSYS    21  // Bad system call.
#define SIGTRAP   22  // Trace/breakpoint trap.
#define SIGURG    23  // High bandwidth data is available at a socket.
#define SIGVTALRM 24  // Virtual timer expired.
#define SIGXCPU   25  // CPU time limit exceeded.
#define SIGXFSZ   26  // File size limit exceeded.

// The following signals are not specified in POSIX.
#define SIGWINCH  27  // Controlling terminal changed size.

#define SIGMAX 27

// sighandler_t constants.
#define SIG_DFL ((ksighandler_t)0x0)
#define SIG_IGN ((ksighandler_t)0x1)

// sa_flags flags.
#define SA_RESTART 1
#define SA_NODEFER 2

// Actions for sigprocmask().
#define SIG_BLOCK 1
#define SIG_UNBLOCK 2
#define SIG_SETMASK 3

// sigaction is the name of both the type and the syscall, so a basic
// '#define sigaction ksigaction' creates problems in compilation (we end up
// with the wrong syscall name in libc).  So do the name selection manually.
#if __APOS_BUILDING_KERNEL__
#  define _APOS_SIGACTION ksigaction
#else
#  define _APOS_SIGACTION sigaction
#endif
struct _APOS_SIGACTION {
  ksighandler_t sa_handler;
  ksigset_t sa_mask;
  int sa_flags;
  // TODO(aoates): support sa_sigaction.
};
typedef struct _APOS_SIGACTION ksigaction_t;
#undef _APOS_SIGACTION

_Static_assert(sizeof(ksigset_t) * 8 >= SIGMAX,
               "sigset_t too small to hold all signals");

static inline int ksigemptyset(ksigset_t* set) {
  *set = 0;
  return 0;
}

static inline int ksigfillset(ksigset_t* set) {
  _Static_assert(sizeof(ksigset_t) == sizeof(uint32_t),
                 "ksigfillset only implemented for uint32_t");
  *set = 0xFFFFFFFF;
  return 0;
}

static inline int ksigaddset(ksigset_t* set, int signum) {
  if (signum <= SIGNULL || signum > SIGMAX) {
    return -EINVAL;
  }
  *set |= (1 << (signum - 1));
  return 0;
}

static inline int ksigdelset(ksigset_t* set, int signum) {
  if (signum <= SIGNULL || signum > SIGMAX) {
    return -EINVAL;
  }
  *set &= ~(1 << (signum - 1));
  return 0;
}

static inline int ksigismember(const ksigset_t* set, int signum) {
  if (signum <= SIGNULL || signum > SIGMAX) {
    return -EINVAL;
  }
  if (*set & (1 << (signum - 1))) {
    return 1;
  } else {
    return 0;
  }
}

// Rename types and functions to POSIX names for user code.
#if !__APOS_BUILDING_KERNEL__
  typedef ksigset_t sigset_t;

# define sigaddset(set, sig) ksigaddset(set, sig)
# define sigdelset(set, sig) ksigdelset(set, sig)
# define sigemptyset(set) ksigemptyset(set)
# define sigfillset(set) ksigfillset(set)
# define sigismember(set, sig) ksigismember(set, sig)

  // Unlike the above types/names, in user mode ksigaction/ksigaction_t is _not_
  // defined (see comment above for why).  But we reference it in syscall stubs.
  // So define it to be the same as sigaction/sigaction_t, which _is_ defined
# define ksigaction sigaction

#endif // !__APOS_BUILDING_KERNEL__

#endif
