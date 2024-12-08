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

/* Constants for the multiboot header */
_MB_MAGIC = 0x1BADB002;
_MB_FLAG_ALIGN = 0x1;
_MB_FLAG_MEMINFO = 0x2;
_MB_FLAGS = _MB_FLAG_ALIGN | _MB_FLAG_MEMINFO;
_MB_CHECKSUM = -(_MB_MAGIC + _MB_FLAGS);

SECTIONS
{
    . = 0x00100000;

    .multiboot_header ALIGN(4) :
    {
        LONG(_MB_MAGIC)
        LONG(_MB_FLAGS)
        LONG(_MB_CHECKSUM)
    }

    .init-text ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.text)
    }

    .init-rodata ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.rodata* .lrodata* .srodata*)
    }

    .init-data ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.data .ldata .sdata)
    }

    .init-bss ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.bss .lbss .sbss)
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
        *(.lrodata*)
        *(.srodata*)
    }

    .data ALIGN (0x1000) : AT(ADDR(.data) - _OFFSET)
    {
        *(.data)
        *(.ldata)
        *(.sdata)
    }

    .bss : AT(ADDR(.bss) - _OFFSET)
    {
        *(COMMON)
        *(.bss)
        *(.lbss)
        *(.sbss)
        KERNEL_END_SYMBOL = .;
    }
}
