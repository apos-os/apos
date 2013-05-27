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

// Code to initialize, install, and manipulate the x86 TSS.
#ifndef APOO_PROC_TSS_H
#define APOO_PROC_TSS_H

#include "common/types.h"

// x86 TSS.  We only use the ESP0 and SS0 fields.
typedef struct {
  uint32_t _unused1;
  uint32_t esp0;
  uint16_t ss0;
  uint16_t _unused2;
  uint32_t _unused3[22];
  uint16_t _unused4;
  uint16_t iombp;
} __attribute__((packed)) tss_t;
_Static_assert(sizeof(tss_t) == 104, "tss_t incorrect size");

// Allocate, initialize, and install a TSS.
//
// You must call tss_set_kernel_stack() before entering user mode.
void tss_init(void);

// Set the current kernel stack in the TSS.  Call when switching threads.
void tss_set_kernel_stack(addr_t stack);

#endif
