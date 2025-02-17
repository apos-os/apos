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

#ifndef APOO_SANITIZERS_TSAN_TSAN_HOOKS_H
#define APOO_SANITIZERS_TSAN_TSAN_HOOKS_H

typedef unsigned long uptr;

typedef int __tsan_atomic32;
typedef int __tsan_mo;

void __tsan_read1(void* addr);
void __tsan_read2(void* addr);
void __tsan_read4(void* addr);
void __tsan_read8(void* addr);
void __tsan_read16(void* addr);

void __tsan_unaligned_read2(void* addr);
void __tsan_unaligned_read4(void* addr);
void __tsan_unaligned_read8(void* addr);

void __tsan_write1(void* addr);
void __tsan_write2(void* addr);
void __tsan_write4(void* addr);
void __tsan_write8(void* addr);
void __tsan_write16(void* addr);

void __tsan_unaligned_write2(void* addr);
void __tsan_unaligned_write4(void* addr);
void __tsan_unaligned_write8(void* addr);

void* __tsan_memcpy(void* dest, const void* src, uptr count);
void* __tsan_memset(void* dest, int ch, uptr count);

void __tsan_func_entry(void* call_pc);
void __tsan_func_exit(void);

__tsan_atomic32 __tsan_atomic32_load(
    const volatile __tsan_atomic32* a, __tsan_mo mo);
void __tsan_atomic32_store(
    volatile __tsan_atomic32* a, __tsan_atomic32 val, __tsan_mo mo);
__tsan_atomic32 __tsan_atomic32_fetch_add(
    volatile __tsan_atomic32* a, __tsan_atomic32 val, __tsan_mo mo);
__tsan_atomic32 __tsan_atomic32_fetch_sub(
    volatile __tsan_atomic32* a, __tsan_atomic32 val, __tsan_mo mo);

#endif
