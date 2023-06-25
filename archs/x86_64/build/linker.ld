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
_OFFSET = 0xFFFFFFFFC0000000;

/* Constants for the multiboot header */
_MB_MAGIC = 0x1BADB002;
_MB_FLAG_ALIGN = 0x1;
_MB_FLAG_MEMINFO = 0x2;
_MB_FLAGS = _MB_FLAG_ALIGN | _MB_FLAG_MEMINFO;
_MB_CHECKSUM = -(_MB_MAGIC + _MB_FLAGS);

SECTIONS
{

    . = 0x00001000;
    .multiboot_header ALIGN(4) :
    {
        LONG(_MB_MAGIC)
        LONG(_MB_FLAGS)
        LONG(_MB_CHECKSUM)
    }
    . = 0x00100000;

    /* TODO(aoates): fix alignment so that we don't end up with RWX LOADs.  Does
     * that matter?  Changing to ALIGN(0x1000000) allows ld to make independent
     * LOAD segments, but needs to be evaluated for physical memory use.
     */
    .init-text ALIGN(0x1000) :
    {
        libkernel_phys.a(.text)
    }

    .init-rodata ALIGN(0x1000) :
    {
        libkernel_phys.a(.rodata*)
    }

    .init-data ALIGN(0x1000) :
    {
        libkernel_phys.a(.data)
    }

    .init-bss ALIGN(0x1000) :
    {
        libkernel_phys.a(.bss)
    }

    /* Load the main part of the kernel in virtual memory */
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
