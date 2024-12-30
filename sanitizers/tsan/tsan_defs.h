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

#ifndef APOO_SANITIZERS_TSAN_TSAN_DEFS_H
#define APOO_SANITIZERS_TSAN_TSAN_DEFS_H

#include "common/config.h"
#include "sanitizers/tsan/tsan_params.h"

// STACK_SIZE_MULTIPLIER is set to a multiplier if TSAN is enabled, otherwise 1.
#if ENABLE_TSAN
#define STACK_SIZE_MULTIPLIER TSAN_STACK_MULT
#else
#define STACK_SIZE_MULTIPLIER 1
#endif

#endif
