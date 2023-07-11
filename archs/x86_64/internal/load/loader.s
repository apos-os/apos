# Copyright 2015 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.global loader                          # making entry point visible to linker

# reserve initial kernel stack space
.set STACKSIZE, 0x8000                  # that is, 32k.
.lcomm stack, STACKSIZE                 # reserve stack on a doubleword boundary
.lcomm  mbd, 4                          # we will use this in kmain
.lcomm  magic, 4                        # we will use this in kmain

.balign 0x1000
PML4: .space 0x1000, 0
PDPT: .space 0x1000, 0
PD: .space 0x1000, 0

.balign 8
GDT: .space 24, 0
.balign 4
.space 2, 0
GDT_PTR: .space 10, 0

loader:
.code32
    movl  $(stack + STACKSIZE), %esp    # set up the stack
    movl  %eax, magic                   # Multiboot magic number
    movl  %ebx, mbd                     # Multiboot data structure

    # Enable PAE.
    movl %cr4, %eax
    or $0x20, %eax
    movl %eax, %cr4

    # Set up paging structures.
    movl $(PDPT), %eax
    or $0x00000003, %eax
    movl %eax, PML4
    movl $0, (PML4 + 4)

    # PDPT
    movl $(PD), %eax
    or $0x00000003, %eax
    movl %eax, PDPT

    # Page directory (identity-mapped 2MB pages).
    movl $0x00000083, PD
    movl $0x00200083, (PD + 8)
    movl $0x00400083, (PD + 16)

    # Install page tables.
    movl $(PDPT), %eax
    movl %eax, %cr3

    # Enter IA32e mode
    mov $0xc0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr

    # Enable paging.
    movl %cr0, %eax
    or $0x80010000, %eax
    movl %eax, %cr0

    # Create a GDT.
    movl $0x00209a00, (GDT + 12)
    movl $0x00209200, (GDT + 20)
    mov $24, %ax
    mov %ax, (GDT_PTR)

    # Load GDT.
    movl $(GDT), (GDT_PTR + 2)
    movl $(GDT_PTR), %eax
    lgdt (%eax)

    # Jump to 64-bit mode.
    ljmp $0x8, $tgt64

.code64
tgt64:
    # Use our 64-bit data segment for all data segment registers.
    mov $0x10, %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    # Set up GDT and IDT.
    call gdt_init
    call idt_init

    movl magic, %edi
    movl mbd, %esi
    movl $(stack), %edx
    callq mem_init

    # We're now running in virtual memory!
    # Pass the memory_info_t* returned by mem_init to kinit.  kinit is linked
    # in the virtual address space, and will undo the identity-mapping of the
    # first XMB set up by mem_init.  It will then call kmain.
    mov %rax, %rdi
    call  kinit

    cli
hang:
    hlt                                 # halt machine should kernel return
    jmp   hang
