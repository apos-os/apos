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

#ifndef APOO_SANITIZERS_TSAN_INTERNAL_TYPES_H
#define APOO_SANITIZERS_TSAN_INTERNAL_TYPES_H

#include <stdint.h>

// An epoch counter.
typedef uint32_t tsan_epoch_t;

#define TSAN_EPOCH_BITS 32
#define TSAN_EPOCH_MAX ((1LL << TSAN_EPOCH_BITS) - 1)

// A thread ID (globally unique).
typedef uint16_t tsan_tid_t;

// A thread slot ID.
typedef uint8_t tsan_sid_t;

#endif
