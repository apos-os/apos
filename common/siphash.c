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
#include "common/siphash.h"

#include "common/endian.h"
#include "common/kstring.h"

#define ROTL(x, bits) ((x << bits) | (x >> (64 - bits)))

#define SIP_ROUND()    \
  do {                 \
    v0 += v1;          \
    v2 += v3;          \
                       \
    v1 = ROTL(v1, 13); \
    v3 = ROTL(v3, 16); \
                       \
    v1 ^= v0;          \
    v3 ^= v2;          \
                       \
    v0 = ROTL(v0, 32); \
                       \
    v2 += v1;          \
    v0 += v3;          \
                       \
    v1 = ROTL(v1, 17); \
    v3 = ROTL(v3, 21); \
                       \
    v1 ^= v2;          \
    v3 ^= v0;          \
    v2 = ROTL(v2, 32); \
  } while (0)

uint64_t siphash_2_4(const uint64_t key[2], const void* data, ssize_t len) {
  // This may or may not be endian-correct...I'm not sure.
  uint64_t v0 = key[0] ^ 0x736f6d6570736575;
  uint64_t v1 = key[1] ^ 0x646f72616e646f6d;
  uint64_t v2 = key[0] ^ 0x6c7967656e657261;
  uint64_t v3 = key[1] ^ 0x7465646279746573;

  for (ssize_t i = 0; i < len / 8; ++i) {
    uint64_t m_i;
    kmemcpy(&m_i, &((const uint8_t*)data)[i * 8], 8);
    m_i = htol64(m_i);
    v3 ^= m_i;
    SIP_ROUND();
    SIP_ROUND();
    v0 ^= m_i;
  }

  // Do the final bit.
  int bytes_left = len % 8;
  uint64_t m_i = (uint64_t)len << 56;
  kmemcpy(&m_i, &((const uint8_t*)data)[len - bytes_left], bytes_left);
  m_i = htol64(m_i);

  v3 ^= m_i;
  SIP_ROUND();
  SIP_ROUND();
  v0 ^= m_i;

  v2 ^= 0xff;
  SIP_ROUND();
  SIP_ROUND();
  SIP_ROUND();
  SIP_ROUND();
  return v0 ^ v1 ^ v2 ^ v3;
}
