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

#include "common/kassert.h"
#include "common/types.h"
#include "memory/gdt.h"
#include "proc/kthread.h"
#include "syscall/context.h"

syscall_context_t syscall_extract_context() {
  _Static_assert(sizeof(addr_t) == sizeof(uint32_t),
                 "x86 syscall_extract_context used on incompatible platform");

  syscall_context_t context;
  uint32_t* stack_ptr = (uint32_t*)kthread_kernel_stack_top();
  stack_ptr--;  // The first slot is garbage.
  context.ss = *(stack_ptr--);
  context.esp = *(stack_ptr--);
  context.cs = *(stack_ptr--);
  context.eip = *(stack_ptr--);

  KASSERT(context.ss == ((GDT_USER_DATA_SEGMENT << 3) | 0x03));
  KASSERT(context.cs == ((GDT_USER_CODE_SEGMENT << 3) | 0x03));
  return context;
}

void syscall_apply_context(syscall_context_t context, uint32_t retval) {
  KASSERT(context.ss == ((GDT_USER_DATA_SEGMENT << 3) | 0x03));
  KASSERT(context.cs == ((GDT_USER_CODE_SEGMENT << 3) | 0x03));

  // TODO(aoates): do we want to merge this with the code in proc/user_mode.c?
  asm volatile (
      "mov %0, %%eax\n\t"
      "mov %%ax, %%ds\n\t"
      "mov %%ax, %%es\n\t"
      "mov %%ax, %%fs\n\t"
      "mov %%ax, %%gs\n\t"
      "pushl %0\n\t"
      "pushl %1\n\t"
      "pushl %2\n\t"
      "pushl %3\n\t"
      "mov %4, %%eax\n\t"
      "lret"
      :: "r"(context.ss), "r"(context.esp),
         "r"(context.cs), "r"(context.eip), "r"(retval) : "eax");

  // Never get here.
}
