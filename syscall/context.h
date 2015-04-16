// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SYSCALL_CONTEXT_H
#define APOO_SYSCALL_CONTEXT_H

#include "user/include/apos/posix_signal.h"

// Indicates that there is a separate signal mask that should be set just before
// returning to userspace (as per sigsuspend() and friends).
#define SCCTX_RESTORE_MASK 1

// Indicates the current syscall can be restarted if it returns -EINTR.
#define SCCTX_RESTARTABLE 2

typedef struct {
  // Signal mask to restore just before returning to userspace, if flags
  // includes SCCTX_RESTORE_MASK.
  sigset_t restore_mask;

  int flags;
} syscall_context_t;

#endif
