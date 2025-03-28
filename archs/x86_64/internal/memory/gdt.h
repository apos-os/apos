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

#ifndef APOO_ARCHS_X86_64_ARCH_MEMORY_GDT_H
#define APOO_ARCHS_X86_64_ARCH_MEMORY_GDT_H

#include <stdbool.h>
#include <stdint.h>

#include "common/multilink.h"
#include "common/types.h"

// Common segment indices.
#define GDT_NUM_ENTRIES 10

#define GDT_NULL_SEGMENT 0
#define GDT_KERNEL_CODE_SEGMENT 1
#define GDT_KERNEL_DATA_SEGMENT 2
#define GDT_USER_CODE_SEGMENT_32 3
#define GDT_USER_DATA_SEGMENT_32 4
#define GDT_SYSCALL_CALL_GATE 6
#define GDT_SYSCALL_CALL_GATE_UPPER 7
#define GDT_TSS 8
#define GDT_TSS_UPPER 9

#define RPL_KERNEL 0
#define RPL_USER 3

// Create a segment selector for the given segment and RPL.
static inline uint16_t segment_selector(uint16_t segment, uint16_t rpl) {
  return (segment << 3) | rpl;
}

typedef enum {
  SEG_CODE,
  SEG_DATA,
} gdt_seg_type_t;

typedef enum {
  GATE_CALL,
} gdt_gate_type_t;

typedef struct { uint32_t data[2]; } gdt_entry_t;

typedef struct {
  uint16_t limit;    // Limit of the GDT (last valid byte; # of entries * 8 - 1)
  uint64_t base;     // Linear address of the GDT.
} __attribute__((packed)) gdt_ptr_t;
_Static_assert(sizeof(gdt_ptr_t) == 10, "gdt_ptr_t incorrect size");

// Create a GDT segment entry with the given parameters.
gdt_entry_t MULTILINK(gdt_entry_create_segment) (
    uint32_t base, uint32_t limit, gdt_seg_type_t type,
    uint8_t flags, uint8_t dpl, uint8_t granularity,
    bool is64bit);

void MULTILINK(gdt_entry_create_tss) (addr_t base, gdt_entry_t entry[2]);

// Create a GDT gate entry with the given parameters.  Returns how many entries
// (of 8 bytes each) are consumed.
// TODO(aoates): unify this with the IDT gate creation code.
int MULTILINK(gdt_entry_create_gate) (
    addr_t offset, uint16_t seg_selector, gdt_gate_type_t type, uint8_t dpl,
    gdt_entry_t* out);

// Install the given GDT pointer and flush all segment registers.
void MULTILINK(gdt_flush) (gdt_ptr_t* gdt_ptr);

// Install a segment in the GDT at the given index.
void MULTILINK(gdt_install_segment) (int index, gdt_entry_t entry);

#endif
