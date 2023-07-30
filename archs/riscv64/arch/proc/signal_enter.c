// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "archs/riscv64/internal/constants.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/math.h"
#include "syscall/dmz.h"

extern char sigreturn_trampoline_start;
extern char sigreturn_trampoline_end;

// Copy the given buffer onto the given stack, and return the new stack pointer
// (which is also the address of the buffer on the stack).
// TODO(aoates): perhaps combine this with the stack manipulation code in exec.c
static inline addr_t* push_buffer(const void* buf, size_t len, addr_t* stack) {
  const size_t len_words = ceiling_div(len, sizeof(addr_t));
  addr_t* dest = stack - len_words;
  if (syscall_copy_to_user(buf, dest, len) < 0) {
    // TODO(aoates): handle this error properly.
    klogfm(KL_PROC, WARNING,
           "Unable to push signal handler (buf=0x%" PRIxADDR " len=%zu\n",
           (addr_t)dest, len);
  }
  return dest;
}

// Push a single word onto the stack.
static inline addr_t* push(addr_t value, addr_t* stack) {
  return push_buffer(&value, sizeof(value), stack);
}

void proc_run_user_sighandler(int signum, const ksigaction_t* action,
                              const ksigset_t* old_mask,
                              const user_context_t* context,
                              const syscall_context_t* syscall_ctx) {
  addr_t* stack = (addr_t*)context->ctx.sp;

  // First push the old signal mask, context, and trampoline.
  stack = push_buffer(old_mask, sizeof(ksigset_t), stack);
  const addr_t old_mask_addr = (addr_t)stack;

  stack = push_buffer(context, sizeof(user_context_t), stack);
  const addr_t context_addr = (addr_t)stack;

  if (syscall_ctx)
    stack = push_buffer(syscall_ctx, sizeof(syscall_context_t), stack);
  const addr_t syscall_context_addr = syscall_ctx ? (addr_t)stack : 0x0;

  const size_t tramp_len = (addr_t)&sigreturn_trampoline_end -
      (addr_t)&sigreturn_trampoline_start;
  stack = push_buffer(&sigreturn_trampoline_start, tramp_len, stack);
  const addr_t trampoline_addr = (addr_t)stack;

  // If necessary, add a buffer dword to make sure the stack ends up aligned.
  if ((addr_t)stack % RSV_STACK_ALIGN == 0) {
    stack--;
  }

  // First push the address of the old mask and context, for the trampoline to
  // access after the handler finishes.
  stack = push(old_mask_addr, stack);
  stack = push(context_addr, stack);
  stack = push(syscall_context_addr, stack);
  KASSERT_DBG((addr_t)stack % RSV_STACK_ALIGN == 0);

  // Set up the call frame for the signal handler.
  user_context_t new_ctx;
  kmemset(&new_ctx, 0, sizeof(new_ctx));
  new_ctx.ctx.a0 = signum;
  new_ctx.ctx.ra = trampoline_addr;
  new_ctx.ctx.sp = (addr_t)stack;
  new_ctx.ctx.address = (addr_t)action->sa_handler;

  user_context_apply(&new_ctx);
  die("unreachable");
}
