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

#include "archs/i586/internal/memory/gdt.h"
#include "arch/dev/interrupts.h"
#include "arch/proc/user_mode.h"
#include "arch/proc/user_context.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/types.h"

void user_mode_enter(addr_t stack, addr_t entry) {
  user_context_t ctx;
  _Static_assert(sizeof(addr_t) == sizeof(ctx.esp),
                 "Invalid addr_t size for i386 code");
  kmemset(&ctx, 0, sizeof(user_context_t));
  ctx.type = USER_CONTEXT_INTERRUPT;
  ctx.esp = stack;
  ctx.eip = entry;
  asm volatile(
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(ctx.eflags));
  ctx.eflags |= IF_FLAG;

  user_context_apply(&ctx);
  // Never get here.
}
