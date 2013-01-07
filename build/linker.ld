/*
 * Copyright 2014 Andrew Oates.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

ENTRY (loader)

/* NOTE: keep this in sync with the constant in paging.c */
_OFFSET = 0xC0000000;

/*NOTE: keep the list of manually-placed object files in sync with the one in
 * the Makefile, to prevent duplicate symbols.
 */
SECTIONS
{
    . = 0x00100000;

    .multiboot_header :
    {
        load/multiboot.o
    }

    .init-text ALIGN(0x1000) :
    {
      load/loader.o(.text .rodata .data .bss)
      load/mem_init.o(.text .rodata .data .bss)
      load/gdt.o(.text .rodata .data .bss)
      load/gdt_flush.o(.text .rodata .data .bss)
      load/idt.o(.text .rodata .data .bss)
    }

    /* Load the main part of the kernel at VMA 0xC0000000. */
    . += _OFFSET;

    KERNEL_START_SYMBOL = .;
    .text ALIGN (0x1000) : AT(ADDR(.text) - _OFFSET)
    {
        *(.text)
    }

    .rodata ALIGN (0x1000) : AT(ADDR(.rodata) - _OFFSET)
    {
        *(.rodata*)
    }

    .data ALIGN (0x1000) : AT(ADDR(.data) - _OFFSET)
    {
        *(.data)
    }

    .bss : AT(ADDR(.bss) - _OFFSET)
    {
        *(COMMON)
        *(.bss)
        KERNEL_END_SYMBOL = .;
    }
}
