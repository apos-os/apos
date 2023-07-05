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

#ifndef APOO_COMMON_MATH_H
#define APOO_COMMON_MATH_H

#include <stdint.h>

#define min(a, b) \
 ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
   _a < _b ? _a : _b; })

#define max(a, b) \
 ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
   _a > _b ? _a : _b; })

// Does integer division of a by b, but takes the ceiling of the result, not the
// floor.
#define ceiling_div(a, b) \
 ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
    (_a % _b) ? _a / _b + 1 : _a / _b; })

// Does integer division of a by b, but rounds to the nearest quotient instead
// of truncating.
#define round_nearest_div(a, b) \
 ({ typeof (a) _a = (a); \
     typeof (b) _b = (b); \
    (_a + (_b / 2)) / _b; })

// Aligns the given number to the next multiple of |align|.
static inline uint64_t align_up(uint64_t x, uint32_t align) {
  return ((x - 1) + (align - ((x - 1) % align)));
}

#endif
