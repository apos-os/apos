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

#ifndef APOO_TEST_TSAN_INSTRUMENTED_H
#define APOO_TEST_TSAN_INSTRUMENTED_H

#include <stdint.h>

// Reads the given value, then stores an incremented value back to the pointer.
void tsan_rw_value(int* x);
void tsan_rw_u64(uint64_t* x);

uint8_t tsan_read8(uint8_t* x);
void tsan_write8(uint8_t* x, uint8_t val);

uint16_t tsan_read16(uint16_t* x);
void tsan_write16(uint16_t* x, uint16_t val);

uint32_t tsan_read32(uint32_t* x);
void tsan_write32(uint32_t* x, uint32_t val);

uint64_t tsan_read64(uint64_t* x);
void tsan_write64(uint64_t* x, uint64_t val);

// Functions to force unaligned reads/writes at a given address.
uint16_t tsan_unaligned_read16(void* x);
void tsan_unaligned_write16(void* x, uint16_t val);

uint32_t tsan_unaligned_read32(void* x);
void tsan_unaligned_write32(void* x, uint32_t val);

uint64_t tsan_unaligned_read64(void* x);
void tsan_unaligned_write64(void* x, uint64_t val);

#endif
