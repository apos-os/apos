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

#ifndef APOO_HASH_H
#define APOO_HASH_H

#include <stdint.h>

#include "common/config.h"
#include "common/types.h"

static const uint32_t kFNVOffsetBasis = 2166136261;
static const uint32_t kFNVPrime = 16777619;

static inline uint32_t fnv_hash(uint32_t key) {
  uint32_t h = kFNVOffsetBasis;
  h ^= (key & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 8) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 16) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 24) & 0xFF);
  h *= kFNVPrime;
  return h;
}

static inline uint32_t fnv_hash64(uint64_t key) {
  uint32_t h = kFNVOffsetBasis;
  h ^= (key & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 8) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 16) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 24) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 32) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 40) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 48) & 0xFF);
  h *= kFNVPrime;
  h ^= ((key >> 56) & 0xFF);
  h *= kFNVPrime;
  return h;
}

static inline uint32_t fnv_hash_array(const void* buf, int len) {
  uint32_t h = kFNVOffsetBasis;
  for (int i = 0; i < len; ++i) {
    h ^= ((uint8_t*)buf)[i];
    h *= kFNVPrime;
  }
  return h;
}

static inline uint32_t fnv_hash_concat(uint32_t a, uint32_t b) {
  uint32_t buf[2];
  buf[0] = a;
  buf[1] = b;
  return fnv_hash_array(buf, sizeof(uint32_t) * 2);
}

#if ARCH_IS_64_BIT
_Static_assert(sizeof(addr_t) == sizeof(uint64_t), "bad addr_t size");
#  define fnv_hash_addr fnv_hash64
#else
_Static_assert(sizeof(addr_t) == sizeof(uint32_t), "bad addr_t size");
#  define fnv_hash_addr fnv_hash
#endif

// Compute the MD5 digest of the given buffer.
void md5_hash(const void* buf, int buflen, uint8_t md5_out[16]);

#endif
