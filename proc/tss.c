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

#include "archs/i586/internal/memory/gdt.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/types.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "proc/tss.h"

// Our single TSS.  Align on a 256-byte boundary to ensure it doesn't cross a
// page boundary.
static tss_t g_tss __attribute__((aligned (256)));

void tss_init() {
  KASSERT(g_tss.ss0 == 0);
  kmemset(&g_tss, 0, sizeof(tss_t));
  g_tss.ss0 = segment_selector(GDT_KERNEL_DATA_SEGMENT, RPL_KERNEL);
  g_tss.iombp = sizeof(tss_t);  // No IOBMP.

  // Create a segment descriptor for the TSS.
  const gdt_entry_t desc = gdt_entry_create_segment(
      (uint32_t)&g_tss, sizeof(tss_t) - 1, SEG_TSS,
      0, 0, 0);
  gdt_install_segment(GDT_TSS, desc);

  // Load the descriptor into the task register.
  const uint16_t selector = GDT_TSS * sizeof(gdt_entry_t);
  asm volatile (
      "ltr %0"
      :: "mr"(selector));
}

void tss_set_kernel_stack(addr_t stack) {
  _Static_assert(sizeof(stack) == sizeof(g_tss.esp0),
                 "can't fit stack address into TSS");
  KASSERT(g_tss.ss0 != 0);
  g_tss.esp0 = (uint32_t)stack;
}
