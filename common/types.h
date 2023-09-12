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
#include <stddef.h>

#include "arch/common/types.h"
#include "user/include/apos/posix_types.h"

typedef uint32_t addr32_t;
typedef uint64_t addr64_t;

_Static_assert(sizeof(size_t) == sizeof(addr_t), "bad size_t size");
_Static_assert(sizeof(ssize_t) == sizeof(size_t), "bad ssize_t size");

#endif
