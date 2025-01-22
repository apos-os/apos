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
#include "sanitizers/tsan/tsan_hooks.h"

#include "common/kassert.h"
#include "common/kstring-tsan.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/tsan_access.h"
#include "sanitizers/tsan/tsan_event.h"

#define TSAN_CHECK_ALIGNMENT 1

#if TSAN_CHECK_ALIGNMENT
# define CHECK_ALIGNMENT(ptr, align) \
    KASSERT((addr_t)(ptr) % (align) == 0)
#else
# define CHECK_ALIGNMENT(ptr, align)
#endif

void __tsan_init(void) {}

void __tsan_read1(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 1, TSAN_ACCESS_READ);
}

void __tsan_read2(void* addr) {
  CHECK_ALIGNMENT(addr, 2);
  tsan_check(CALLERPC, (addr_t)addr, 2, TSAN_ACCESS_READ);
}

void __tsan_read4(void* addr) {
  CHECK_ALIGNMENT(addr, 4);
  tsan_check(CALLERPC, (addr_t)addr, 4, TSAN_ACCESS_READ);
}

void __tsan_read8(void* addr) {
  CHECK_ALIGNMENT(addr, 8);
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_READ);
}

void __tsan_read16(void* addr) {
  CHECK_ALIGNMENT(addr, 8);
  // TODO(tsan): is this kind of split correct?
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_READ);
  tsan_check(CALLERPC, (addr_t)addr + 8, 8, TSAN_ACCESS_READ);
}

void __tsan_unaligned_read2(void* addr) {
  tsan_check_unaligned(CALLERPC, (addr_t)addr, 2, TSAN_ACCESS_READ);
}

void __tsan_unaligned_read4(void* addr) {
  tsan_check_unaligned(CALLERPC, (addr_t)addr, 4, TSAN_ACCESS_READ);
}

void __tsan_unaligned_read8(void* addr) {
  tsan_check_unaligned(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_READ);
}

void __tsan_write1(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 1, TSAN_ACCESS_WRITE);
}

void __tsan_write2(void* addr) {
  CHECK_ALIGNMENT(addr, 2);
  tsan_check(CALLERPC, (addr_t)addr, 2, TSAN_ACCESS_WRITE);
}

void __tsan_write4(void* addr) {
  CHECK_ALIGNMENT(addr, 4);
  tsan_check(CALLERPC, (addr_t)addr, 4, TSAN_ACCESS_WRITE);
}

void __tsan_write8(void* addr) {
  CHECK_ALIGNMENT(addr, 8);
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_WRITE);
}

void __tsan_write16(void* addr) {
  CHECK_ALIGNMENT(addr, 8);
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_WRITE);
  tsan_check(CALLERPC, (addr_t)addr + 8, 8, TSAN_ACCESS_WRITE);
}

void __tsan_unaligned_write2(void* addr) {
  tsan_check_unaligned(CALLERPC, (addr_t)addr, 2, TSAN_ACCESS_WRITE);
}

void __tsan_unaligned_write4(void* addr) {
  tsan_check_unaligned(CALLERPC, (addr_t)addr, 4, TSAN_ACCESS_WRITE);
}

void __tsan_unaligned_write8(void* addr) {
  tsan_check_unaligned(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_WRITE);
}

void* __tsan_memcpy(void* dest, const void* src, uptr count) {
  tsan_check_range(CALLERPC, (addr_t)src, count, TSAN_ACCESS_READ);
  tsan_check_range(CALLERPC, (addr_t)dest, count, TSAN_ACCESS_WRITE);
  return kmemcpy_no_tsan(dest, src, count);
}

void* __tsan_memset(void* dest, int ch, uptr count) {
  tsan_check_range(CALLERPC, (addr_t)dest, count, TSAN_ACCESS_WRITE);
  return kmemset_no_tsan(dest, ch, count);
}

void __tsan_func_entry(void* call_pc) {
  if (g_tsan_init) {
    tsan_log_func_entry(&tsan_current_thread()->tsan.log,
                        (addr_t)call_pc - SIZE_OF_JUMP_INSTR);
  }
}

void __tsan_func_exit(void) {
  if (g_tsan_init) {
    tsan_log_func_exit(&tsan_current_thread()->tsan.log);
  }
}
