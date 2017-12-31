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

#ifndef APOO_ARCHS_I586_ARCH_COMMON_ENDIAN_H
#define APOO_ARCHS_I586_ARCH_COMMON_ENDIAN_H

#include <stdint.h>

#include "arch/common/endian.h"

// Convert host-to-little endian values.
static inline uint16_t htol16(uint16_t val) { return val; }
static inline uint32_t htol32(uint32_t val) { return val; }

static inline uint16_t ltoh16(uint16_t val) { return val; }
static inline uint32_t ltoh32(uint32_t val) { return val; }

// Convert host-to-big endian values.
// TODO(aoates): these can be in an arch-independent place.
static inline uint16_t htob16(uint16_t val) {
  return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

static inline uint32_t htob32(uint32_t val) {
  return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
         ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

static inline uint16_t btoh16(uint16_t val) { return htob16(val); }

static inline uint32_t btoh32(uint32_t val) { return htob32(val); }

#endif
