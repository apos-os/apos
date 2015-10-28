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

#include <stdint.h>

#include "archs/x86_64/internal/memory/gdt.h"
#include "archs/x86_64/internal/proc/tss.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/types.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"

// Our single TSS.  Align on a 256-byte boundary to ensure it doesn't cross a
// page boundary.
static tss_t g_tss __attribute__((aligned (256)));

void tss_init() {
  kmemset(&g_tss, 0, sizeof(tss_t));
  g_tss.iombp = sizeof(tss_t);  // No IOBMP.

  // Create a segment descriptor for the TSS.
  gdt_entry_t desc[2];
  gdt_entry_create_tss((addr_t)&g_tss, desc);
  gdt_install_segment(GDT_TSS, desc[0]);
  gdt_install_segment(GDT_TSS_UPPER, desc[1]);

  // Load the descriptor into the task register.
  const uint16_t selector = GDT_TSS * sizeof(gdt_entry_t);
  asm volatile (
      "ltr %0"
      :: "mr"(selector));
}

void tss_set_kernel_stack(addr_t stack) {
  _Static_assert(sizeof(stack) == sizeof(g_tss.rsp0),
                 "can't fit stack address into TSS");
  g_tss.rsp0 = (uint64_t)stack;
}
