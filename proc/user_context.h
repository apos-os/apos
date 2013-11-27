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

#ifndef APOO_PROC_USER_CONTEXT_H
#define APOO_PROC_USER_CONTEXT_H

#include <stdint.h>

#include "common/types.h"

typedef enum {
  USER_CONTEXT_CALL_GATE = 1,
  USER_CONTEXT_INTERRUPT = 2,
} user_context_type_t;

// Context from a switch from user mode into kernel mode, e.g. from an interrupt
// or syscall.  Can be saved and used to restore the context later without the
// original kernel stack (e.g. after forking or invoking a signal handler).
typedef struct {
  user_context_type_t type;

  uint32_t esp;
  uint32_t eip;

  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;

  // Only if type == USER_CONTEXT_INTERRUPT.
  uint32_t eflags;
} user_context_t;

// Apply an user-mode context on the current stack to return to user-space.
// Does not delete the context.  Does not return.
void user_context_apply(const user_context_t* context);

#endif
