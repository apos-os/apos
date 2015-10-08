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
#include "archs/x86_64/internal/memory/gdt.h"
#include "common/kassert.h"
#include "common/types.h"

// Defined in user_context_asm.s
typedef uint32_t reg_t;
void x86_64_userret_callgate(const user_context_t* ctx)
    __attribute__((noreturn));
void x86_64_userret_interrupt(const user_context_t* ctx)
    __attribute__((noreturn));

void user_context_apply(const user_context_t* ctx) {
  // Make sure it matches the constants in user_mode_asm.s.
  KASSERT_DBG(segment_selector(GDT_USER_DATA_SEGMENT_32, RPL_USER) == 0x23);
  KASSERT_DBG(segment_selector(GDT_USER_CODE_SEGMENT_32, RPL_USER) == 0x1b);

  // TODO(aoates): merge this with the code in proc/user_mode.c
  switch (ctx->type) {
    case USER_CONTEXT_CALL_GATE:
      KASSERT_DBG(get_interrupts_state());
      x86_64_userret_callgate(ctx);
      break;

    case USER_CONTEXT_INTERRUPT:
      KASSERT_DBG(ctx->rflags & IF_FLAG);
      x86_64_userret_interrupt(ctx);
      break;
  }

  die("unreachable");
  // Never get here.
}
