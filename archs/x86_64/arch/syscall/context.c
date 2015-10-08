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

#include "arch/syscall/context.h"
#include "archs/x86_64/internal/memory/gdt.h"
#include "archs/x86-common/internal/proc/kthread.h"
#include "common/kassert.h"
#include "common/types.h"
#include "proc/kthread.h"

user_context_t syscall_extract_context(long retval) {
  _Static_assert(sizeof(addr_t) == sizeof(uint64_t),
                 "x86 syscall_extract_context used on incompatible platform");
  _Static_assert(sizeof(long) == sizeof(uint64_t),
                 "x86 syscall_extract_context used on incompatible platform");

  user_context_t context;
  context.type = USER_CONTEXT_CALL_GATE;
  context.is64 = false;  // TODO(aoates): determine this dynamically.

  // TODO(aoates): this shouldn't have access to kthread_current_thread().
  uint64_t* stack_ptr =
      (uint64_t*)kthread_arch_kernel_stack_top(kthread_current_thread());
  stack_ptr--;  // The first slot is garbage.
  const uint64_t ss = *(stack_ptr--);
  context.rsp = *(stack_ptr--);
  const uint64_t cs = *(stack_ptr--);
  context.rip = *(stack_ptr--);

  context.rax = (uint64_t)retval;
  if (ENABLE_KERNEL_SAFETY_NETS) {
    context.rbx = 0xABCD;
    context.rcx = 0xABCD;
    context.rdx = 0xABCD;
    context.rsi = 0xABCD;
    context.rdi = 0xABCD;
    context.rbp = 0xABCD;
    context.r8 = 0xABCD;
    context.r9 = 0xABCD;
    context.r10 = 0xABCD;
    context.r11 = 0xABCD;
    context.r12 = 0xABCD;
    context.r13 = 0xABCD;
    context.r14 = 0xABCD;
    context.r15 = 0xABCD;
  }

  KASSERT(ss == segment_selector(GDT_USER_DATA_SEGMENT_32, RPL_USER));
  KASSERT(cs == segment_selector(GDT_USER_CODE_SEGMENT_32, RPL_USER));
  return context;
}

long syscall_get_result(const user_context_t* ctx) {
  _Static_assert(sizeof(long) == sizeof(uint64_t),
                 "x86 syscall_extract_context used on incompatible platform");
  return (long)ctx->rax;
}

void syscall_set_result(user_context_t* ctx, long retval) {
  _Static_assert(sizeof(long) == sizeof(uint64_t),
                 "x86 syscall_extract_context used on incompatible platform");
  KASSERT_DBG(ctx->type == USER_CONTEXT_CALL_GATE);
  ctx->rax = (uint64_t)retval;
}
