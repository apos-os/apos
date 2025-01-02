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
#include "sanitizers/tsan/tsan_access.h"

#define CALLERPC ((uptr)__builtin_return_address(0))

typedef unsigned long uptr;

void __tsan_init(void) {}

// TODO(tsan): pass the current PC in all of these.
void __tsan_read1(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 1, TSAN_ACCESS_READ);
}

void __tsan_read2(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 2, TSAN_ACCESS_READ);
}

void __tsan_read4(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 4, TSAN_ACCESS_READ);
}

void __tsan_read8(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_READ);
}

void __tsan_read16(void* addr) {
  // TODO(tsan): is this kind of split correct?
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_READ);
  tsan_check(CALLERPC, (addr_t)addr + 8, 8, TSAN_ACCESS_READ);
}

void __tsan_unaligned_read2(void* addr) {
  tsan_check_unaligned(0, (addr_t)addr, 2, TSAN_ACCESS_READ);
}

void __tsan_unaligned_read4(void* addr) { die("unimplemented"); }
void __tsan_unaligned_read8(void* addr) { die("unimplemented"); }

void __tsan_write1(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 1, TSAN_ACCESS_WRITE);
}

void __tsan_write2(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 2, TSAN_ACCESS_WRITE);
}

void __tsan_write4(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 4, TSAN_ACCESS_WRITE);
}

void __tsan_write8(void* addr) {
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_WRITE);
}

void __tsan_write16(void* addr) {
  // TODO(tsan): is this kind of split correct?
  tsan_check(CALLERPC, (addr_t)addr, 8, TSAN_ACCESS_WRITE);
  tsan_check(CALLERPC, (addr_t)addr + 8, 8, TSAN_ACCESS_WRITE);
}

void __tsan_unaligned_write2(void* addr) {
  tsan_check_unaligned(0, (addr_t)addr, 2, TSAN_ACCESS_WRITE);
}

// TODO(tsan): handle unaligned ops.
void __tsan_unaligned_write4(void* addr) { die("unimplemented"); }
void __tsan_unaligned_write8(void* addr) { die("unimplemented"); }

void* __tsan_memcpy(void* dest, const void* src, uptr count) {
  // TODO(tsan): handle whole blocks.
  return __builtin_memcpy(dest, src, count);
}

void* __tsan_memset(void* dest, int ch, uptr count) {
  // TODO(tsan): handle whole blocks.
  return __builtin_memset(dest, ch, count);
}

void __tsan_func_entry(void* call_pc) {}
void __tsan_func_exit(void) {}
