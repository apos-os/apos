// Copyright 2018 Andrew Oates.  All Rights Reserved.
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

#include "net/ip/checksum.h"

#include "common/kassert.h"

uint16_t ip_checksum(const void* buf, size_t len) {
  return ip_checksum2(buf, len, NULL, 0);
}

uint16_t ip_checksum2(const void* buf, size_t len, const void* buf2,
                      size_t len2) {
  uint32_t checksum = 0;
  const uint16_t* buf_chunks = (const uint16_t*)buf;
  for (size_t i = 0; i < len / 2; ++i) {
    checksum += buf_chunks[i];
    checksum = (checksum >> 16) + (checksum & 0xFFFF);  // End-around carry.
  }
  if (len % 2 == 1) {
    uint8_t nextb = 0;
    if (buf2) {
      nextb = ((const uint8_t*)buf2)[0];
      buf2 = (const uint8_t*)buf2 + 1;
      len2--;
    }
    uint8_t bridge[2] = {((const uint8_t*)buf)[len - 1], nextb};
    checksum += *(uint16_t*)&bridge;
    checksum = (checksum >> 16) + (checksum & 0xFFFF);  // End-around carry.
  }
  buf_chunks = (const uint16_t*)buf2;
  len = len2;
  for (size_t i = 0; i < len / 2; ++i) {
    checksum += buf_chunks[i];
    checksum = (checksum >> 16) + (checksum & 0xFFFF);  // End-around carry.
  }
  if (len % 2 == 1) {
    uint8_t bridge[2] = {((const uint8_t*)buf2)[len - 1], 0};
    checksum += *(uint16_t*)&bridge;
    checksum = (checksum >> 16) + (checksum & 0xFFFF);  // End-around carry.
  }
  KASSERT_DBG((checksum & 0xFFFF0000) == 0);
  return ~checksum & 0xFFFF;
}
