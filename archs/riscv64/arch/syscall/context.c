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
#include "arch/syscall/context.h"

#include "arch/proc/user_context.h"
#include "archs/riscv64/internal/kthread.h"
#include "internal/constants.h"

user_context_t syscall_extract_context(long retval) {
  // TODO(aoates): this shouldn't have access to kthread_current_thread().
  // TODO(aoates): pass this up from the syscall/interrupt handler in a cleaner
  // way (perhaps in a kthread_t field?).
  addr_t ctx_addr =
      kthread_arch_kernel_stack_bottom(kthread_current_thread()) - 288;
  user_context_t ctx = *(const user_context_t*)ctx_addr;
  ctx.ctx.a0 = retval;
  // Need to modify the return address here as well as interrupts.c, since we'll
  // hit this path when delivering a signal.
  // TODO(aoates): refactor all the syscall and interrupt paths so as not to
  // assume they enter the kernel divergently.
  ctx.ctx.address += RSV_ECALL_INSTR_LEN;
  return ctx;
}

long syscall_get_result(const user_context_t* ctx) {
  return ctx->ctx.a0;
}

void syscall_set_result(user_context_t* ctx, long retval) {
  ctx->ctx.a0 = retval;
}
