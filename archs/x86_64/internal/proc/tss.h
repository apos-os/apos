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

// x86-64 TSS.  We only use the RSP0 field.
typedef struct {
  uint32_t _unused1;
  uint64_t rsp0;
  uint32_t _unused3[6];
  uint64_t ist1;
  uint64_t ist2;
  uint64_t ist3;
  uint64_t ist4;
  uint64_t ist5;
  uint64_t ist6;
  uint64_t ist7;
  uint32_t _unused4[2];
  uint16_t _unused5;
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
