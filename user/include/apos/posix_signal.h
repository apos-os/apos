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
#  include "user/include/apos/_posix_signal_constants.h"
#else
#  include <apos/errors.h>
#  include <apos/_posix_signal_constants.h>
#endif

typedef uint32_t ksigset_t;
typedef void (*ksighandler_t)(int);

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

_Static_assert(sizeof(ksigset_t) * 8 >= APOS_SIGMAX,
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
  if (signum < APOS_SIGMIN || signum > APOS_SIGMAX) {
    return -EINVAL;
  }
  *set |= (1 << (signum - 1));
  return 0;
}

static inline int ksigdelset(ksigset_t* set, int signum) {
  if (signum < APOS_SIGMIN || signum > APOS_SIGMAX) {
    return -EINVAL;
  }
  *set &= ~(1 << (signum - 1));
  return 0;
}

static inline int ksigismember(const ksigset_t* set, int signum) {
  if (signum < APOS_SIGMIN || signum > APOS_SIGMAX) {
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
