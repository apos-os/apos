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

#include "arch/proc/user_mode.h"

#include "arch/proc/user_context.h"
#include "common/kstring.h"

void user_mode_enter(addr_t stack, addr_t entry) {
  user_context_t ctx;
  kmemset(&ctx, 0, sizeof(user_context_t));
  ctx.ctx.sp = stack;
  ctx.ctx.address = entry;
  user_context_apply(&ctx);
  // Never get here
}
