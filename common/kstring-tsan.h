// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

// Non-TSAN versions of low-level string functions.
#ifndef APOO_COMMON_KSTRING_TSAN_H
#define APOO_COMMON_KSTRING_TSAN_H

#include "common/types.h"

void* kmemset_no_tsan(void* s, int c, size_t n);
void* kmemcpy_no_tsan(void* dest, const void* src, size_t n);

#endif
