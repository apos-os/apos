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

#include "common/hash.h"

#include "common/kassert.h"
#include "common/kstring.h"

#define MD5_ASSERT KASSERT_DBG
#define MD5_MEMCPY kmemcpy
#define MD5_MEMSET kmemset
#include "common/md5-impl.c"

static const uint64_t kFNV64OffsetBasis = 0xcbf29ce484222325;
static const uint64_t kFNV64Prime = 0x00000100000001b3;

uint64_t fnv64_hash(uint64_t key) {
  uint64_t h = kFNV64OffsetBasis;
  h ^= (key & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 8) & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 16) & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 24) & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 32) & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 40) & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 48) & 0xFF);
  h *= kFNV64Prime;
  h ^= ((key >> 56) & 0xFF);
  h *= kFNV64Prime;
  return h;
}

uint64_t fnv64_hash_array(const void* buf, int len) {
  uint64_t h = kFNV64OffsetBasis;
  for (int i = 0; i < len; ++i) {
    h ^= ((uint8_t*)buf)[i];
    h *= kFNV64Prime;
  }
  return h;
}

uint64_t fnv64_hash_concat(uint64_t a, uint64_t b) {
  uint64_t buf[2];
  buf[0] = a;
  buf[1] = b;
  return fnv64_hash_array(buf, sizeof(uint64_t) * 2);
}
