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
#include "test/tsan/instrumented.h"

#include <stdint.h>

#if !__has_feature(thread_sanitizer)
#error TSAN must be enabled in this module
#endif

void tsan_rw_value(int* x) {
  int val = *x;
  *x = val + 1;
}

void tsan_rw_u64(uint64_t* x) {
  uint64_t val = *x;
  *x = val + 1;
}

uint8_t tsan_read8(uint8_t* x) {
  return *x;
}

void tsan_write8(uint8_t* x, uint8_t val) {
  *x = val;
}

uint16_t tsan_read16(uint16_t* x) {
  return *x;
}

void tsan_write16(uint16_t* x, uint16_t val) {
  *x = val;
}

uint32_t tsan_read32(uint32_t* x) {
  return *x;
}

void tsan_write32(uint32_t* x, uint32_t val) {
  *x = val;
}

uint64_t tsan_read64(uint64_t* x) {
  return *x;
}

void tsan_write64(uint64_t* x, uint64_t val) {
  *x = val;
}

// Putting it into a packed struct forces clang to use unaligned loads/stores.
typedef struct {
  union {
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
  };
} __attribute__((packed)) unaligned_data_t;

uint16_t tsan_unaligned_read16(void* x) {
  return ((unaligned_data_t*)x)->u16;
}

void tsan_unaligned_write16(void* x, uint16_t val) {
  ((unaligned_data_t*)x)->u16 = val;
}

uint32_t tsan_unaligned_read32(void* x) {
  return ((unaligned_data_t*)x)->u32;
}

void tsan_unaligned_write32(void* x, uint32_t val) {
  ((unaligned_data_t*)x)->u32 = val;
}
