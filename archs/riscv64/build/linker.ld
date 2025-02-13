/*
 * Copyright 2023 Andrew Oates.  All Rights Reserved.
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

INCLUDE archs/riscv64/internal/memlayout.m4.ld

ENTRY (_kstart)

/* TODO(aoates): is this always the case?  This is true for qemu virt. */
_ENTRY_ADDR = 0x80200000;

/* Assuming all the code is linked above _ENTRY_ADDR (which it should be), this
 * puts all kernel code in the last 2GB of virtual memory, which allows it to be
 * linked with the medany code model.
 */
_OFFSET = RSV64_KERNEL_VIRT_OFFSET;

SECTIONS
{
    . = _ENTRY_ADDR;

    /* TODO(aoates): fix alignment so that we don't end up with RWX LOADs.  Does
     * that matter?  Changing to ALIGN(0x1000000) allows ld to make independent
     * LOAD segments, but needs to be evaluated for physical memory use.
     */
    .init-text ALIGN(0x1000) :
    {
        */libkernel_phys.a:loader.PHYS.o(.text)
        */libkernel_phys.a:(.text)
    }

    .init-rodata ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.rodata* .srodata* .lrodata*)
    }

    .init-data ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.data .ldata .sdata)
    }

    .init-bss ALIGN(0x1000) :
    {
        */libkernel_phys.a:(.bss .lbss .sbss)
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
        *(.lrodata*)
        *(.srodata*)
    }

    .data ALIGN (0x1000) : AT(ADDR(.data) - _OFFSET)
    {
        KERNEL_DATA_START = .;
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
    }
    KERNEL_DATA_END = .;
    KERNEL_END_SYMBOL = .;

    . = 0;
    .riscv.attributes : { *(.riscv.attributes) }
    INCLUDE build/common_metadata_sections.ld
}
