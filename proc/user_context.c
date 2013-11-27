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
#include "proc/user_context.h"

void user_context_apply(const user_context_t* context_ptr) {
  // Make a copy on the local stack to free up our registers and let GCC do its
  // thing with the asm constraints.  This isn't strictly necessary but makes
  // things easier.
  const user_context_t context = *context_ptr;

  const uint32_t ss = segment_selector(GDT_USER_DATA_SEGMENT, RPL_USER);
  const uint32_t cs = segment_selector(GDT_USER_CODE_SEGMENT, RPL_USER);

  switch (context.type) {
    case USER_CONTEXT_CALL_GATE:
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
            "mov %5, %%ebx\n\t"
            "mov %6, %%ecx\n\t"
            "mov %7, %%edx\n\t"
            "mov %8, %%esi\n\t"
            "mov %9, %%edi\n\t"
            "mov %10, %%ebp\n\t"
            "lret"
            :: "r"(ss), "r"(context.esp),
            "r"(cs), "r"(context.eip),
            "m"(context.eax), "m"(context.ebx), "m"(context.ecx),
            "m"(context.edx), "m"(context.esi), "m"(context.edi),
            "m"(context.ebp)
         : "eax");
        break;

    // TODO(aoates): merge this with the code in proc/user_mode.c
    case USER_CONTEXT_INTERRUPT:
        asm volatile (
            "mov %0, %%eax\n\t"
            "mov %%ax, %%ds\n\t"
            "mov %%ax, %%es\n\t"
            "mov %%ax, %%fs\n\t"
            "mov %%ax, %%gs\n\t"
            "pushl %0\n\t"
            "pushl %1\n\t"
            "pushl %11\n\t"
            "pushl %2\n\t"
            "pushl %3\n\t"
            "mov %4, %%eax\n\t"
            "mov %5, %%ebx\n\t"
            "mov %6, %%ecx\n\t"
            "mov %7, %%edx\n\t"
            "mov %8, %%esi\n\t"
            "mov %9, %%edi\n\t"
            "mov %10, %%ebp\n\t"
            "iret"
            :: "r"(ss), "r"(context.esp),
            "r"(cs), "r"(context.eip),
            "m"(context.eax), "m"(context.ebx), "m"(context.ecx),
            "m"(context.edx), "m"(context.esi), "m"(context.edi),
            "m"(context.ebp), "r"(context.eflags)
         : "eax");
        break;
  }

  die("unreachable");
  // Never get here.
}
