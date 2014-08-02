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

#ifndef APOO_ARCHS_COMMON_ARCH_PROC_USER_CONTEXT_H
#define APOO_ARCHS_COMMON_ARCH_PROC_USER_CONTEXT_H

// Context from a switch from user mode into kernel mode, e.g. from an interrupt
// or syscall.  Can be saved and used to restore the context later without the
// original kernel stack (e.g. after forking or invoking a signal handler).
//
// The actual definition is architecture-specific.
typedef struct user_context user_context_t;

// Apply an user-mode context on the current stack to return to user-space.
// Does not delete the context.  Does not return.
void user_context_apply(const user_context_t* context);

#endif
