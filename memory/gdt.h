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
#define GDT_NULL_SEGMENT 0
#define GDT_KERNEL_CODE_SEGMENT 1
#define GDT_KERNEL_DATA_SEGMENT 2
#define GDT_USER_CODE_SEGMENT 3
#define GDT_USER_DATA_SEGMENT 4

typedef struct {
   uint16_t limit_low;           // Lower 16 bits of the limit.
   uint16_t base_low;            // Lower 16 bits of the base.
   uint8_t  base_middle;         // Middle 8 bits of the base.
   unsigned int type:4;          // Type of segment.
   unsigned int sys:1;           // System or regular descriptor.
   unsigned int dpl:2;           // Descriptor protection level (ring).
   unsigned int present:1;
   unsigned int limit_high:4;    // Upper 4 bits of the limit.
   unsigned int :2;              // Unused.
   unsigned int db:1;            // Default/bound flag.
   unsigned int granularity:1;   // Limit granularity (0 = bytes, 1 = 4kbs)
   uint8_t  base_high;           // Last 8 bits of the base.
} __attribute__((packed)) gdt_entry_t;
_Static_assert(sizeof(gdt_entry_t) == 8, "gdt_entry_t incorrect size");

typedef struct {
  uint16_t limit;    // Limit of the GDT (last valid byte; # of entries * 8 - 1)
  uint32_t base;     // Linear address of the GDT.
} __attribute__((packed)) gdt_ptr_t;
_Static_assert(sizeof(gdt_ptr_t) == 6, "gdt_ptr_t incorrect size");

// Create a gdt_entry_t with the given parameters.
gdt_entry_t MULTILINK(gdt_entry_create) (
    uint32_t base, uint32_t limit, uint8_t type,
    uint8_t dpl, uint8_t granularity);

void MULTILINK(gdt_flush) (gdt_ptr_t* gdt_ptr);

#endif
