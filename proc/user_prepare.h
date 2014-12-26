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

#ifndef APOO_PROC_USER_PREPARE_H
#define APOO_PROC_USER_PREPARE_H

#include "arch/proc/user_context.h"

// Prepare to return to userspace, e.g. from a syscall or interrupt.  Any
// pending signals will be assigned and dispatched (if possible), the process
// will be stopped if necessary, etc.
//
// The given user-context-extraction function will be called with the argument
// if a user context is needed.
//
// This function may not return.
void proc_prep_user_return(user_context_t (*context_fn)(void*), void* arg);

#endif
