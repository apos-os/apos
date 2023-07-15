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
#include "archs/i586/internal/proc/tss.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/types.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"

// Our single TSS.  Align on a 256-byte boundary to ensure it doesn't cross a
// page boundary.
static tss_t g_tss __attribute__((aligned (256)));

// Special TSS for handling double faults.
static tss_t g_dblfault_tss __attribute__((aligned (256)));

// Special stack for double faults.
#define DBLFAULT_STACK_SIZE 4096
static uint8_t g_dblfault_stack[DBLFAULT_STACK_SIZE]
    __attribute__((aligned(DBLFAULT_STACK_SIZE)));

static void dblfault_handler(void) {
  die("Kernel double fault");
}

void tss_init(void) {
  KASSERT(g_tss.ss0 == 0);
  kmemset(&g_tss, 0, sizeof(tss_t));
  g_tss.ss0 = segment_selector(GDT_KERNEL_DATA_SEGMENT, RPL_KERNEL);
  g_tss.iombp = sizeof(tss_t);  // No IOBMP.

  kmemset(&g_dblfault_tss, 0, sizeof(tss_t));
  g_dblfault_tss.esp = (uint32_t)&g_dblfault_stack + DBLFAULT_STACK_SIZE - 4;
  g_dblfault_tss.eip = (uint32_t)&dblfault_handler;
  g_dblfault_tss.cs = segment_selector(GDT_KERNEL_CODE_SEGMENT, RPL_KERNEL);
  g_dblfault_tss.ss = segment_selector(GDT_KERNEL_DATA_SEGMENT, RPL_KERNEL);
  g_dblfault_tss.iombp = sizeof(tss_t);  // No IOBMP.

  asm volatile(
      "pushf\n\t"
      "pop %0\n\t"
      "movl %%cr3, %1\n\t"
      : "=r"(g_dblfault_tss.eflags), "=r"(g_dblfault_tss.cr3));

  // Create a segment descriptor for the TSS.
  gdt_entry_t desc = gdt_entry_create_segment(
      (uint32_t)&g_tss, sizeof(tss_t) - 1, SEG_TSS,
      0, 0, 0);
  gdt_install_segment(GDT_TSS, desc);

  desc = gdt_entry_create_segment((uint32_t)&g_dblfault_tss, sizeof(tss_t) - 1,
                                  SEG_TSS, 0, 0, 0);
  gdt_install_segment(GDT_TSS_DBLFAULT, desc);

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

const tss_t* tss_get(void) {
  return &g_tss;
}
