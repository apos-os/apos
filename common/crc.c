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
