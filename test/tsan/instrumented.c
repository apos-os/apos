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

#include "common/atomic.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/kstring-tsan.h"

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

uint64_t tsan_unaligned_read64(void* x) {
  return ((unaligned_data_t*)x)->u64;
}

void tsan_unaligned_write64(void* x, uint64_t val) {
  ((unaligned_data_t*)x)->u64 = val;
}

void tsan_test_kmemset(void* dest, int c, size_t n) {
  kmemset(dest, c, n);
}

void tsan_test_kmemcpy(void* dest, const void* src, size_t n) {
  kmemcpy(dest, src, n);
}

void tsan_implicit_memset(tsan_test_struct_t* x) {
  *x = (tsan_test_struct_t){0};
}

void tsan_implicit_memcpy(tsan_test_struct_t* x) {
  tsan_test_struct_t b;
  kmemset_no_tsan(&b, 0x12, sizeof(b));
  *x = b;
}

uint32_t tsan_atomic_read(atomic32_t* x, int memorder) {
  switch (memorder) {
    case ATOMIC_RELAXED:
      return atomic_load_relaxed(x);

    case ATOMIC_ACQUIRE:
      return atomic_load_acquire(x);

    case ATOMIC_ACQ_REL:
      return atomic_add_acq_rel(x, 0);

    case ATOMIC_SEQ_CST:
      return atomic_load_seq_cst(x);
  }
  die("Bad memory order");
}

void tsan_atomic_write(atomic32_t* x, uint32_t val, int memorder) {
  switch (memorder) {
    case ATOMIC_RELAXED:
      atomic_store_relaxed(x, val);
      return;

    case ATOMIC_RELEASE:
      atomic_store_release(x, val);
      return;

    case ATOMIC_ACQ_REL:
      // Not really atomic...
      atomic_add_acq_rel(x, val - atomic_load_relaxed(x));
      return;

    case ATOMIC_SEQ_CST:
      atomic_store_seq_cst(x, val);
      return;
  }
  die("Bad memory order");
}

uint32_t tsan_atomic_rmw(atomic32_t* x, uint32_t val, int memorder) {
  switch (memorder) {
    case ATOMIC_RELAXED:
      return atomic_add_relaxed(x, val);

    case ATOMIC_ACQUIRE:
      return __atomic_add_fetch(&x->_val, val, ATOMIC_ACQUIRE);

    case ATOMIC_RELEASE:
      return __atomic_add_fetch(&x->_val, val, ATOMIC_RELEASE);

    case ATOMIC_ACQ_REL:
      return atomic_add_acq_rel(x, val);
  }
  die("Bad memory order");
}

bool tsan_flag_get(const atomic_flag_t* f) {
  return atomic_flag_get(f);
}

void tsan_flag_set(atomic_flag_t* f) {
  atomic_flag_set(f);
}

void tsan_flag_clear(atomic_flag_t* f) {
  atomic_flag_clear(f);
}
