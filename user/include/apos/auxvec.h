// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

// An auxiliary info vector based on Linux's, for passing additional low-level
// information to an executed binary.
#ifndef APOO_USER_INCLUDE_APOS_AUXVEC_H
#define APOO_USER_INCLUDE_APOS_AUXVEC_H

#include <stdint.h>

typedef struct {
  uint32_t a_type;
  uint32_t a_val;
  uint32_t a_val_hi;  // For 64-bit platforms, the upper 32 bits.
} apos_auxv_t;

// Values for a_type.  Intentionally not named the same as on Linux, as the
// semantics may not exactly match.
#define AUXVEC_NULL 0
#define AUXVEC_PAGESZ 1
#define AUXVEC_BASE 2
#define AUXVEC_MAX 2

// Userspace utilities for accessing auxvec data.
unsigned long apos_auxval_get(unsigned long type);

#endif
