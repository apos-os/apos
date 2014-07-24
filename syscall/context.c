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
#include "archs/i586/internal/proc/kthread.h"
#include "common/kassert.h"
#include "common/types.h"
#include "proc/kthread.h"
#include "syscall/context.h"

user_context_t syscall_extract_context(long retval) {
  _Static_assert(sizeof(addr_t) == sizeof(uint32_t),
                 "x86 syscall_extract_context used on incompatible platform");
  _Static_assert(sizeof(long) == sizeof(uint32_t),
                 "x86 syscall_extract_context used on incompatible platform");

  user_context_t context;
  context.type = USER_CONTEXT_CALL_GATE;

  // TODO(aoates): this shouldn't have access to kthread_current_thread().
  uint32_t* stack_ptr =
      (uint32_t*)kthread_arch_kernel_stack_top(kthread_current_thread());
  stack_ptr--;  // The first slot is garbage.
  const uint32_t ss = *(stack_ptr--);
  context.esp = *(stack_ptr--);
  const uint32_t cs = *(stack_ptr--);
  context.eip = *(stack_ptr--);

  context.eax = (uint32_t)retval;
  context.ebx = 0xABCD;
  context.ecx = 0xABCD;
  context.edx = 0xABCD;
  context.esi = 0xABCD;
  context.edi = 0xABCD;
  context.ebp = 0xABCD;

  KASSERT(ss == segment_selector(GDT_USER_DATA_SEGMENT, RPL_USER));
  KASSERT(cs == segment_selector(GDT_USER_CODE_SEGMENT, RPL_USER));
  return context;
}
