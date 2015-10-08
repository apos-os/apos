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

#ifndef APOO_ARCHS_X86_64_ARCH_PROC_USER_CONTEXT_H
#define APOO_ARCHS_X86_64_ARCH_PROC_USER_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include "archs/common/arch/proc/user_context.h"
#include "common/types.h"

typedef enum {
  USER_CONTEXT_CALL_GATE = 1,
  USER_CONTEXT_INTERRUPT = 2,
} user_context_type_t;

// Context from a switch from user mode into kernel mode, e.g. from an interrupt
// or syscall.  Can be saved and used to restore the context later without the
// original kernel stack (e.g. after forking or invoking a signal handler).
struct user_context {
  uint64_t rsp;
  uint64_t rbp;
  uint64_t rip;

  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;

  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;

  // Only if type == USER_CONTEXT_INTERRUPT.
  uint64_t rflags;

  user_context_type_t type;
  bool is64;  // Did we come from a 64-bit process?
} __attribute__((packed));

#endif
