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

#include "archs/x86_64/internal/dev/interrupts-x86.h"
#include "archs/x86_64/internal/load/mem_init.h"
#include "archs/x86_64/internal/memory/gdt.h"
#include "archs/x86_64/internal/memory/page_tables.h"
#include "memory/memory.h"

extern void kmain(memory_info_t* meminfo);

// Glue function in between 'all-physical' setup code and 'all-virtual' kernel
// code.  Tears down temporary mappings set up by paging initialization and
// finishes transfer to fully-virtual memory space.
//
// Unlike everything else in load/, is linked at it's VIRTUAL address.  It's
// invoked after paging is setup, at which point we're running completely in
// higher-half mode.  So it unmaps the first 4MB that were needed while paging
// was being initialized, and jumps to kmain.
void kinit(memory_info_t* meminfo) {
  // First, switch our stack to the virtual version (we're currently running on
  // an identity-mapped physical stack).
  asm volatile (
      "movq %%rsp, %%rax;"
      "add %0, %%rax;"
      "movq %%rax, %%rsp;"
      "movq %%rbp, %%rax;"
      "add %0, %%rax;"
      "movq %%rax, %%rbp;"
      :: "i"(KERNEL_VIRT_START) : "rax");

  // Also switch our GDT and IDT pointers to their virtual addresses.
  gdt_ptr_t gdt_ptr;
  asm volatile (
      "sgdt (%0);"
      :: "r"((addr_t)&gdt_ptr) :);
  gdt_ptr.base += KERNEL_VIRT_START;
  gdt_flush(&gdt_ptr);

  idt_ptr_t idt_ptr;
  asm volatile (
      "sidt (%0);"
      :: "r"((addr_t)&idt_ptr) :);
  idt_ptr.base += KERNEL_VIRT_START;
  asm volatile (
      "lidt (%0);"
      :: "r"((addr_t)&idt_ptr) :);

  // Unmap the identity mappings we were using.
  // TODO(aoates): reclaim the pages.
  // TODO(aoates): actually do this.
  kmain(meminfo);

  // We can't ever return or we'll page fault!
  while(1);
}
