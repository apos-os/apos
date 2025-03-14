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

#include "archs/x86_64/internal/memory/gdt.h"
#include "arch/proc/user_mode.h"
#include "common/kassert.h"
#include "common/types.h"
#include "proc/kthread-internal.h"

void user_mode_enter(addr_t stack, addr_t entry) {
  _Static_assert(sizeof(addr_t) == sizeof(uint64_t),
                 "Invalid addr_t size for x86-64 code");

  kthread_reset_interrupt_level();

  const uint64_t new_data_seg =
      segment_selector(GDT_USER_DATA_SEGMENT_32, RPL_USER);
  const uint64_t new_code_seg =
      segment_selector(GDT_USER_CODE_SEGMENT_32, RPL_USER);
  asm volatile (
      "sti\n\t"
      "mov %0, %%rax\n\t"
      "mov %%ax, %%ds\n\t"
      "mov %%ax, %%es\n\t"
      "mov %%ax, %%fs\n\t"
      "mov %%ax, %%gs\n\t"
      "pushq %0\n\t"
      "pushq %1\n\t"
      "pushf\n\t"
      "pushq %2\n\t"
      "pushq %3\n\t"
      "iretq"
      :: "r"(new_data_seg), "r"(stack),
         "r"(new_code_seg), "r"(entry) : "rax");

  // Never get here.
}
