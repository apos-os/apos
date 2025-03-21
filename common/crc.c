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
#include "common/crc.h"

#include <stdbool.h>

uint32_t crc32(const uint8_t* msg, size_t len, uint32_t poly) {
  uint32_t reg = 0xffffffff;
  for (size_t i = 0; i < len; ++i) {
    uint8_t c = msg[i];
    for (int j = 0; j < 8; ++j) {
      if ((reg ^ c) & 0x01) {
        reg = (reg >> 1) ^ poly;
      } else {
        reg >>= 1;
      }
      c >>= 1;
    }
  }
  return ~reg;
}

static const uint8_t kRev8Table[256] = {
    0x00,  // 0x00
    0x80,  // 0x01
    0x40,  // 0x02
    0xc0,  // 0x03
    0x20,  // 0x04
    0xa0,  // 0x05
    0x60,  // 0x06
    0xe0,  // 0x07
    0x10,  // 0x08
    0x90,  // 0x09
    0x50,  // 0x0a
    0xd0,  // 0x0b
    0x30,  // 0x0c
    0xb0,  // 0x0d
    0x70,  // 0x0e
    0xf0,  // 0x0f
    0x08,  // 0x10
    0x88,  // 0x11
    0x48,  // 0x12
    0xc8,  // 0x13
    0x28,  // 0x14
    0xa8,  // 0x15
    0x68,  // 0x16
    0xe8,  // 0x17
    0x18,  // 0x18
    0x98,  // 0x19
    0x58,  // 0x1a
    0xd8,  // 0x1b
    0x38,  // 0x1c
    0xb8,  // 0x1d
    0x78,  // 0x1e
    0xf8,  // 0x1f
    0x04,  // 0x20
    0x84,  // 0x21
    0x44,  // 0x22
    0xc4,  // 0x23
    0x24,  // 0x24
    0xa4,  // 0x25
    0x64,  // 0x26
    0xe4,  // 0x27
    0x14,  // 0x28
    0x94,  // 0x29
    0x54,  // 0x2a
    0xd4,  // 0x2b
    0x34,  // 0x2c
    0xb4,  // 0x2d
    0x74,  // 0x2e
    0xf4,  // 0x2f
    0x0c,  // 0x30
    0x8c,  // 0x31
    0x4c,  // 0x32
    0xcc,  // 0x33
    0x2c,  // 0x34
    0xac,  // 0x35
    0x6c,  // 0x36
    0xec,  // 0x37
    0x1c,  // 0x38
    0x9c,  // 0x39
    0x5c,  // 0x3a
    0xdc,  // 0x3b
    0x3c,  // 0x3c
    0xbc,  // 0x3d
    0x7c,  // 0x3e
    0xfc,  // 0x3f
    0x02,  // 0x40
    0x82,  // 0x41
    0x42,  // 0x42
    0xc2,  // 0x43
    0x22,  // 0x44
    0xa2,  // 0x45
    0x62,  // 0x46
    0xe2,  // 0x47
    0x12,  // 0x48
    0x92,  // 0x49
    0x52,  // 0x4a
    0xd2,  // 0x4b
    0x32,  // 0x4c
    0xb2,  // 0x4d
    0x72,  // 0x4e
    0xf2,  // 0x4f
    0x0a,  // 0x50
    0x8a,  // 0x51
    0x4a,  // 0x52
    0xca,  // 0x53
    0x2a,  // 0x54
    0xaa,  // 0x55
    0x6a,  // 0x56
    0xea,  // 0x57
    0x1a,  // 0x58
    0x9a,  // 0x59
    0x5a,  // 0x5a
    0xda,  // 0x5b
    0x3a,  // 0x5c
    0xba,  // 0x5d
    0x7a,  // 0x5e
    0xfa,  // 0x5f
    0x06,  // 0x60
    0x86,  // 0x61
    0x46,  // 0x62
    0xc6,  // 0x63
    0x26,  // 0x64
    0xa6,  // 0x65
    0x66,  // 0x66
    0xe6,  // 0x67
    0x16,  // 0x68
    0x96,  // 0x69
    0x56,  // 0x6a
    0xd6,  // 0x6b
    0x36,  // 0x6c
    0xb6,  // 0x6d
    0x76,  // 0x6e
    0xf6,  // 0x6f
    0x0e,  // 0x70
    0x8e,  // 0x71
    0x4e,  // 0x72
    0xce,  // 0x73
    0x2e,  // 0x74
    0xae,  // 0x75
    0x6e,  // 0x76
    0xee,  // 0x77
    0x1e,  // 0x78
    0x9e,  // 0x79
    0x5e,  // 0x7a
    0xde,  // 0x7b
    0x3e,  // 0x7c
    0xbe,  // 0x7d
    0x7e,  // 0x7e
    0xfe,  // 0x7f
    0x01,  // 0x80
    0x81,  // 0x81
    0x41,  // 0x82
    0xc1,  // 0x83
    0x21,  // 0x84
    0xa1,  // 0x85
    0x61,  // 0x86
    0xe1,  // 0x87
    0x11,  // 0x88
    0x91,  // 0x89
    0x51,  // 0x8a
    0xd1,  // 0x8b
    0x31,  // 0x8c
    0xb1,  // 0x8d
    0x71,  // 0x8e
    0xf1,  // 0x8f
    0x09,  // 0x90
    0x89,  // 0x91
    0x49,  // 0x92
    0xc9,  // 0x93
    0x29,  // 0x94
    0xa9,  // 0x95
    0x69,  // 0x96
    0xe9,  // 0x97
    0x19,  // 0x98
    0x99,  // 0x99
    0x59,  // 0x9a
    0xd9,  // 0x9b
    0x39,  // 0x9c
    0xb9,  // 0x9d
    0x79,  // 0x9e
    0xf9,  // 0x9f
    0x05,  // 0xa0
    0x85,  // 0xa1
    0x45,  // 0xa2
    0xc5,  // 0xa3
    0x25,  // 0xa4
    0xa5,  // 0xa5
    0x65,  // 0xa6
    0xe5,  // 0xa7
    0x15,  // 0xa8
    0x95,  // 0xa9
    0x55,  // 0xaa
    0xd5,  // 0xab
    0x35,  // 0xac
    0xb5,  // 0xad
    0x75,  // 0xae
    0xf5,  // 0xaf
    0x0d,  // 0xb0
    0x8d,  // 0xb1
    0x4d,  // 0xb2
    0xcd,  // 0xb3
    0x2d,  // 0xb4
    0xad,  // 0xb5
    0x6d,  // 0xb6
    0xed,  // 0xb7
    0x1d,  // 0xb8
    0x9d,  // 0xb9
    0x5d,  // 0xba
    0xdd,  // 0xbb
    0x3d,  // 0xbc
    0xbd,  // 0xbd
    0x7d,  // 0xbe
    0xfd,  // 0xbf
    0x03,  // 0xc0
    0x83,  // 0xc1
    0x43,  // 0xc2
    0xc3,  // 0xc3
    0x23,  // 0xc4
    0xa3,  // 0xc5
    0x63,  // 0xc6
    0xe3,  // 0xc7
    0x13,  // 0xc8
    0x93,  // 0xc9
    0x53,  // 0xca
    0xd3,  // 0xcb
    0x33,  // 0xcc
    0xb3,  // 0xcd
    0x73,  // 0xce
    0xf3,  // 0xcf
    0x0b,  // 0xd0
    0x8b,  // 0xd1
    0x4b,  // 0xd2
    0xcb,  // 0xd3
    0x2b,  // 0xd4
    0xab,  // 0xd5
    0x6b,  // 0xd6
    0xeb,  // 0xd7
    0x1b,  // 0xd8
    0x9b,  // 0xd9
    0x5b,  // 0xda
    0xdb,  // 0xdb
    0x3b,  // 0xdc
    0xbb,  // 0xdd
    0x7b,  // 0xde
    0xfb,  // 0xdf
    0x07,  // 0xe0
    0x87,  // 0xe1
    0x47,  // 0xe2
    0xc7,  // 0xe3
    0x27,  // 0xe4
    0xa7,  // 0xe5
    0x67,  // 0xe6
    0xe7,  // 0xe7
    0x17,  // 0xe8
    0x97,  // 0xe9
    0x57,  // 0xea
    0xd7,  // 0xeb
    0x37,  // 0xec
    0xb7,  // 0xed
    0x77,  // 0xee
    0xf7,  // 0xef
    0x0f,  // 0xf0
    0x8f,  // 0xf1
    0x4f,  // 0xf2
    0xcf,  // 0xf3
    0x2f,  // 0xf4
    0xaf,  // 0xf5
    0x6f,  // 0xf6
    0xef,  // 0xf7
    0x1f,  // 0xf8
    0x9f,  // 0xf9
    0x5f,  // 0xfa
    0xdf,  // 0xfb
    0x3f,  // 0xfc
    0xbf,  // 0xfd
    0x7f,  // 0xfe
    0xff,  // 0xff
};

static uint8_t rev8(uint8_t x) {
  return kRev8Table[x];
}

static uint16_t rev16(uint16_t x) {
  return (rev8(x & 0xff) << 8) | rev8(x >> 8);
}

static uint32_t rev32(uint32_t x) {
  return (rev16(x & 0xffff) << 16) | rev16(x >> 16);
}

uint32_t ether_crc32(const uint8_t* msg, size_t len) {
  uint32_t poly = CRC32_NET_POLY;
  uint32_t reg = 0xffffffff;
  for (size_t i = 0; i < len; ++i) {
    reg ^= msg[i];
    for (int j = 0; j < 8; ++j) {
      if (reg & 1) {
        reg = (reg >> 1) ^ poly;
      } else {
        reg >>= 1;
      }
    }
  }
  return rev32(reg);
}
