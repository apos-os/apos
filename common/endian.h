// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
//
// Functions for manipulating endiannes.
#ifndef APOO_COMMON_ENDIAN_H
#define APOO_COMMON_ENDIAN_H

#include <stdint.h>

static inline uint16_t _bswap16(uint16_t val) {
  return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

static inline uint32_t _bswap32(uint32_t val) {
  return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
         ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

static inline uint64_t _bswap64(uint64_t val) {
  return ((val & 0xFF) << 56) | ((val & 0xFF00) << 40) |
         ((val & 0xFF0000) << 24) | ((val & 0xFF000000) << 8) |
         ((val & 0xFF00000000) >> 8) | ((val & 0xFF0000000000) >> 24) |
         ((val & 0xFF000000000000) >> 40) | ((val & 0xFF00000000000000) >> 56);
}

// Convert host-to-big endian values.
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#  error Big endian not yet supported
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

// Convert host-to-little endian values.
#define ltoh16(x) (x)
#define ltoh32(x) (x)
#define ltoh64(x) (x)
#define htol16(x) (x)
#define htol32(x) (x)
#define htol64(x) (x)

// Convert host-to-big endian values.
#define btoh16(x) _bswap16(x)
#define btoh32(x) _bswap32(x)
#define btoh64(x) _bswap64(x)
#define htob16(x) _bswap16(x)
#define htob32(x) _bswap32(x)
#define htob64(x) _bswap64(x)

#endif

#endif
