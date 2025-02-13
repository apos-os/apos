// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SANITIZERS_TSAN_TSAN_LAYOUT_H
#define APOO_SANITIZERS_TSAN_TSAN_LAYOUT_H

#include "arch/memory/layout.h"
#include "sanitizers/tsan/tsan_defs.h"

// Hard-coded memory layout parameters.  We hard-code so that they can be easily
// optimized, and because in practice they are always set the same.
#define TSAN_MAPPED_START_ADDR RSV64_TSAN_MAPPED_START
#define TSAN_MAPPED_LEN_ADDR RSV64_TSAN_MAPPED_LEN
#define TSAN_SHADOW_START_ADDR RSV64_TSAN_SHADOW_START
#define TSAN_SHADOW_LEN RSV64_TSAN_SHADOW_LEN

// Hard-code these for fast calculations on most accesses.
#define TSAN_HEAP_START_ADDR RSV64_HEAP_START
#define TSAN_HEAP_LEN_ADDR RSV64_HEAP_LEN
#define TSAN_HEAP_END_ADDR (TSAN_HEAP_START_ADDR + TSAN_HEAP_LEN_ADDR)

// Per-page metadata block.
#define TSAN_PAGE_METADATA_START RSV64_TSAN_MDATA_START

#endif
