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

#include "arch/proc/signal/signal_enter.h"

#include "arch/proc/user_context.h"
#include "arch/proc/user_mode.h"
#include "common/kassert.h"
#include "common/math.h"
#include "common/kstring.h"
#include "proc/process.h"
#include "user/include/apos/posix_signal.h"

extern char sigreturn_trampoline_start;
extern char sigreturn_trampoline_end;

// Copy the given buffer onto the given stack, and return the new stack pointer
// (which is also the address of the buffer on the stack).
// TODO(aoates): perhaps combine this with the stack manipulation code in exec.c
static inline addr_t* push_buffer(const void* buf, size_t len, addr_t* stack) {
  KASSERT_DBG((addr_t)stack % sizeof(addr_t) == 0);

  const size_t len_words = ceiling_div(len, sizeof(addr_t));
  kmemcpy(stack - len_words, buf, len);
  return stack - len_words;
}

// Push a single word onto the stack.
static inline addr_t* push(addr_t value, addr_t* stack) {
  return push_buffer(&value, sizeof(addr_t), stack);
}

void proc_run_user_sighandler(int signum, const sigaction_t* action,
                              const sigset_t* old_mask,
                              const user_context_t* context) {
  _Static_assert(sizeof(addr_t) == sizeof(uint32_t),
                 "Invalid addr_t size for i386 code");

  // TODO(aoates): verify that the user-space stack has enough space for
  // everything we need to push onto it.

  addr_t* stack = (addr_t*)context->esp;

  // First push the old signal mask, context, and trampoline.
  stack = push_buffer(old_mask, sizeof(sigset_t), stack);
  const addr_t old_mask_addr = (addr_t)stack;

  stack = push_buffer(context, sizeof(user_context_t), stack);
  const addr_t context_addr = (addr_t)stack;

  const size_t tramp_len = (addr_t)&sigreturn_trampoline_end -
      (addr_t)&sigreturn_trampoline_start;
  stack = push_buffer(&sigreturn_trampoline_start, tramp_len, stack);
  const addr_t trampoline_addr = (addr_t)stack;

  // First push the address of the old mask and context, for the trampoline to
  // access.
  stack = push(old_mask_addr, stack);
  stack = push(context_addr, stack);

  // Then push the call frame for the signal handler (signum arg and return
  // address, which is the trampoline).
  stack = push(signum, stack);
  stack = push(trampoline_addr, stack);

  user_mode_enter((addr_t)stack, (addr_t)action->sa_handler);
  die("unreachable");
}
