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

#ifndef APOO_PROC_SIGNAL_SIGNAL_ENTER_H
#define APOO_PROC_SIGNAL_SIGNAL_ENTER_H

#include "arch/proc/user_context.h"
#include "syscall/context.h"
#include "user/include/apos/posix_signal.h"

// Enter user-space to run the given signal handler.  Deals with the
// architecture-specific setup of the user mode stack, return trampoline, etc.
//
// When the user-mode handler returns, it will jump back into the kernel via a
// sigreturn syscall, which will pop the signal state and restore the original
// user context running when the signal was first dispatched.
//
// Does not return.
void proc_run_user_sighandler(int signum, const sigaction_t* action,
                              const sigset_t* old_mask,
                              const user_context_t* context,
                              const syscall_context_t* syscall_ctx);

#endif
