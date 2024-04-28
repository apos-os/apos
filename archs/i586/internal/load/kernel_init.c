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

#include "archs/i586/internal/dev/interrupts-x86.h"
#include "archs/i586/internal/load/mem_init.h"
#include "archs/i586/internal/memory/gdt.h"
#include "archs/i586/internal/memory/page_tables.h"
#include "common/kstring.h"
#include "main/kernel.h"
#include "memory/memory.h"

#define CMD_LINE_MAX_LEN 256
static char g_command_line[CMD_LINE_MAX_LEN + 1];

// Glue function in between 'all-physical' setup code and 'all-virtual' kernel
// code.  Tears down temporary mappings set up by paging initialization and
// finishes transfer to fully-virtual memory space.
//
// Unlike everything else in load/, is linked at it's VIRTUAL address.  It's
// invoked after paging is setup, at which point we're running completely in
// higher-half mode.  So it unmaps the first 4MB that were needed while paging
// was being initialized, and jumps to kmain.
void kinit(memory_info_t* meminfo, const multiboot_info_t* mb_phys) {
  // First, switch our stack to the virtual version (we're currently running on
  // an identity-mapped physical stack).
  asm volatile (
      "movl %%esp, %%eax;"
      "add %0, %%eax;"
      "movl %%eax, %%esp;"
      "movl %%ebp, %%eax;"
      "add %0, %%eax;"
      "movl %%eax, %%ebp;"
      :: "i"(KERNEL_VIRT_START) : "eax");

  // Also switch our GDT and IDT pointers to their virtual addresses.
  gdt_ptr_t gdt_ptr;
  asm volatile (
      "sgdt (%1);"
      : "=m"(gdt_ptr)
      : "r"((uint32_t)&gdt_ptr) :);
  gdt_ptr.base += KERNEL_VIRT_START;
  gdt_flush(&gdt_ptr);

  idt_ptr_t idt_ptr;
  asm volatile (
      "sidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);
  idt_ptr.base += KERNEL_VIRT_START;
  asm volatile (
      "lidt (%0);"
      :: "r"((uint32_t)&idt_ptr) :);

  // If available, copy the command line from the MB header.
  if (mb_phys->flags & MULTIBOOT_INFO_CMDLINE) {
    const char* cmdline_phys = (const char*)(addr_t)mb_phys->cmdline;
    g_command_line[CMD_LINE_MAX_LEN] = '\0';
    kstrncpy(g_command_line, cmdline_phys, CMD_LINE_MAX_LEN);
  }

  // setup_paging() in mem_init.c identity-maps the first N PDE entries.  We
  // want to undo that.  The page directory is self-mapped at the end of the
  // address space.
  uint32_t* page_directory = (uint32_t*)0xFFFFF000;
  for (int i = 0; i < KERNEL_MAP_4MB_REGIONS; ++i) {
    page_directory[i] = 0 | PDE_WRITABLE;
  }
  boot_info_t boot = {
    .meminfo = meminfo,
    .dtree = NULL,
  };
  kmain(&boot, g_command_line);

  // We can't ever return or we'll page fault!
  while(1);
}
