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

#include "common/errno.h"
#include "common/types.h"
#include "proc/signal/posix_signal.h"

static inline int ksigemptyset(sigset_t* set) {
  *set = 0;
  return 0;
}

static inline int ksigfillset(sigset_t* set) {
  _Static_assert(sizeof(sigset_t) == sizeof(uint32_t),
                 "ksigfillset only implemented for uint32_t");
  *set = 0xFFFFFFFF;
  return 0;
}

static inline int ksigaddset(sigset_t* set, int signum) {
  if (signum <= SIGNULL || signum > SIGMAX) {
    return -EINVAL;
  }
  *set |= (1 << (signum - 1));
  return 0;
}

static inline int ksigdelset(sigset_t* set, int signum) {
  if (signum <= SIGNULL || signum > SIGMAX) {
    return -EINVAL;
  }
  *set &= ~(1 << (signum - 1));
  return 0;
}

static inline int ksigismember(const sigset_t* set, int signum) {
  if (signum <= SIGNULL || signum > SIGMAX) {
    return -EINVAL;
  }
  if (*set & (1 << (signum - 1))) {
    return 1;
  } else {
    return 0;
  }
}

static inline int ksigisemptyset(const sigset_t* set) {
  return (*set == 0) ? 1 : 0;
}

// Send a signal to the given process, as per kill(2).  Returns 0 on success, or
// -errno on error.
int proc_kill(pid_t pid, int sig);

#endif
