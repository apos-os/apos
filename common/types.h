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

// Common types.  See common/posix_types.h for POSIX-required types.
#ifndef APOO_COMMON_TYPES_H
#define APOO_COMMON_TYPES_H

#include <stdint.h>

#include "common/posix_types.h"

// A (virtual) memory address.
// TODO(aoates): replace all uses of uint32_t with addr_t (where appropriate).
typedef uint32_t addr_t;

// A physical memory address.
typedef addr_t phys_addr_t;

// A length or delta of memory bytes.
typedef addr_t addrdiff_t;

#endif
