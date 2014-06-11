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

static const uint32_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static const uint32_t md5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static uint32_t rotl(uint32_t x, uint32_t y) {
  KASSERT_DBG(y < 32);
  return (x << y) | (x >> (32 - y));
}

// Calculate the MD5 hash of a single 512-bit block.
static void md5_hash_block(const void* block, uint32_t md5_out[4]) {
  uint32_t A = md5_out[0];
  uint32_t B = md5_out[1];
  uint32_t C = md5_out[2];
  uint32_t D = md5_out[3];

  for (int i = 0; i < 64; ++i) {
    uint32_t F, g;
    if (i < 16) {
      F = (B & C) | ((~B) & D);
      g = i;
    } else if (i < 32) {
      F = (D & B) | ((~D) & C);
      g = (5 * i + 1) % 16;
    } else if ( i < 48) {
      F = B ^ C ^ D;
      g = (3 * i + 5) % 16;
    } else {
      F = C ^ (B | (~D));
      g = (7 * i) % 16;
    }
    uint32_t old_D = D;
    D = C;
    C = B;
    B += rotl(A + F + md5_K[i] + ((uint32_t*)block)[g], md5_s[i]);
    A = old_D;
  }

  md5_out[0] += A;
  md5_out[1] += B;
  md5_out[2] += C;
  md5_out[3] += D;
}

void md5_hash(const void* bufv, int buflen, uint8_t md5_out[16]) {
  // Calculate how long the final block needs to be.
  const int final_block_orig_len = buflen % 64;
  uint8_t final_block[128];
  kmemcpy(final_block, bufv + (buflen - final_block_orig_len),
          final_block_orig_len);

  int final_block_len, zero_padding_len;
  if (final_block_orig_len + 1 + 8 <= 64) {
    zero_padding_len = 64 - 1 - 8 - final_block_orig_len;
    final_block_len = 64;
  } else {
    zero_padding_len = 128 - 1 - 8 - final_block_orig_len;
    final_block_len = 128;
  }
  final_block[final_block_orig_len] = 0x80;
  kmemset(final_block + final_block_orig_len + 1, 0x00, zero_padding_len);

  // Append the length as a little-endian 64-bit number.
  const uint64_t buflen_bits_64 = buflen * 8;
  for (int i = 0; i < 8; ++i) {
    final_block[1 + final_block_orig_len + zero_padding_len + i] =
        (buflen_bits_64 >> (i * 8)) & 0xFF;
  }

  uint32_t md5[4];

  md5[0] = 0x67452301;
  md5[1] = 0xefcdab89;
  md5[2] = 0x98badcfe;
  md5[3] = 0x10325476;

  for (int i = 0; i < buflen / 64; i++) {
    md5_hash_block(bufv + (i * 64), md5);
  }
  for (int i = 0; i < final_block_len / 64; i++) {
    md5_hash_block(final_block + (i * 64), md5);
  }

  for (int i = 0; i < 16; i++) {
    md5_out[i] = md5[i / 4] >> ((i % 4) * 8);
  }
}
