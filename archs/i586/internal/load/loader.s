# Copyright 2014 Andrew Oates.  All Rights Reserved.
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

# Reserve initial kernel stack space.
# Keep this in sync with mem_init.c.
.set STACKSIZE, 0x4000                  # that is, 16k.
.lcomm stack, STACKSIZE                 # reserve 16k stack on a doubleword boundary
.lcomm  mbd, 4                          # we will use this in kmain
.lcomm  magic, 4                        # we will use this in kmain

loader:
    movl  $(stack + STACKSIZE), %esp    # set up the stack
    movl  %eax, magic                   # Multiboot magic number
    movl  %ebx, mbd                     # Multiboot data structure

    # Set up GDT and paging.  Note: neither gdt_init nor idt_init should touch
    # any memory outside that statically allocated to the kernel (until
    # mem_init has a chance to copy the multiboot struct).
    call gdt_init

    # Set up IDT.
    call idt_init

    pushl $(stack)
    pushl mbd
    pushl magic
    call mem_init

    # We're now running in virtual memory!
    # Pass the memory_info_t* returned by mem_init to kinit.  kinit is linked
    # in the virtual address space, and will undo the identity-mapping of the
    # first 4MB set up by mem_init.  It will then call kmain.
    pushl %eax
    call  kinit

    cli
hang:
    hlt                                 # halt machine should kernel return
    jmp   hang
