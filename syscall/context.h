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

#ifndef APOO_SYSCALL_CONTEXT_H
#define APOO_SYSCALL_CONTEXT_H

#include "proc/user_context.h"

// Extract the syscall_context_t from the current thread's kernel stack.
//
// REQUIRES: a syscall be executing currently.
user_context_t syscall_extract_context(void);

// Apply an extracted syscall context on the current stack to return to
// user-space.  Uses the given value for the syscall return value.  Does not
// return.
void syscall_apply_context(user_context_t context, uint32_t retval);

#endif
