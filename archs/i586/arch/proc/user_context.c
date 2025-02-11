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

#include "arch/proc/user_context.h"
#include "arch/dev/interrupts.h"
#include "archs/i586/internal/memory/gdt.h"
#include "common/kassert.h"
#include "common/types.h"
#include "proc/kthread-internal.h"

// Defined in user_context_asm.s
typedef uint32_t reg_t;
void i586_userret_callgate(reg_t esp, reg_t eip, reg_t eax, reg_t ebx,
                           reg_t ecx, reg_t edx, reg_t esi, reg_t edi,
                           reg_t ebp) __attribute__((noreturn));
void i586_userret_interrupt(reg_t esp, reg_t eip, reg_t eax, reg_t ebx,
                            reg_t ecx, reg_t edx, reg_t esi, reg_t edi,
                            reg_t ebp, reg_t eflags) __attribute__((noreturn));

void user_context_apply(const user_context_t* ctx) {
  // Make sure it matches the constants in user_mode_asm.s.
  KASSERT_DBG(segment_selector(GDT_USER_DATA_SEGMENT, RPL_USER) == 0x23);
  KASSERT_DBG(segment_selector(GDT_USER_CODE_SEGMENT, RPL_USER) == 0x1b);

  kthread_reset_interrupt_level();

  switch (ctx->type) {
    case USER_CONTEXT_CALL_GATE:
      KASSERT_DBG(get_interrupts_state());
      i586_userret_callgate(ctx->esp, ctx->eip, ctx->eax, ctx->ebx, ctx->ecx,
                            ctx->edx, ctx->esi, ctx->edi, ctx->ebp);
      break;

    case USER_CONTEXT_INTERRUPT:
      KASSERT_DBG(ctx->eflags & IF_FLAG);
      i586_userret_interrupt(ctx->esp, ctx->eip, ctx->eax, ctx->ebx, ctx->ecx,
                             ctx->edx, ctx->esi, ctx->edi, ctx->ebp,
                             ctx->eflags);
      break;
  }

  die("unreachable");
  // Never get here.
}
