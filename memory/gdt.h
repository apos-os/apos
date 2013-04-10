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

#ifndef APOO_MEMORY_GDT_H
#define APOO_MEMORY_GDT_H

#include <stdint.h>

#include "common/multilink.h"

// Common segment indices.
#define GDT_NUM_ENTRIES 6

#define GDT_NULL_SEGMENT 0
#define GDT_KERNEL_CODE_SEGMENT 1
#define GDT_KERNEL_DATA_SEGMENT 2
#define GDT_USER_CODE_SEGMENT 3
#define GDT_USER_DATA_SEGMENT 4
#define GDT_TSS 5

typedef enum {
  SEG_CODE,
  SEG_DATA,
  SEG_TSS,
} gdt_seg_type_t;

typedef struct { uint32_t data[2]; } gdt_entry_t;

typedef struct {
  uint16_t limit;    // Limit of the GDT (last valid byte; # of entries * 8 - 1)
  uint32_t base;     // Linear address of the GDT.
} __attribute__((packed)) gdt_ptr_t;
_Static_assert(sizeof(gdt_ptr_t) == 6, "gdt_ptr_t incorrect size");

// Create a gdt_entry_t with the given parameters.
gdt_entry_t MULTILINK(gdt_entry_create) (
    uint32_t base, uint32_t limit, gdt_seg_type_t type,
    uint8_t flags, uint8_t dpl, uint8_t granularity);

// Install the given GDT pointer and flush all segment registers.
void MULTILINK(gdt_flush) (gdt_ptr_t* gdt_ptr);

// Install a segment in the GDT at the given index.
void MULTILINK(gdt_install_segment) (int index, gdt_entry_t entry);

#endif
