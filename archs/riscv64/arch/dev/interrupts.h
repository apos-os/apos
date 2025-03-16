// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#ifndef APOO_ARCHS_RISCV64_ARCH_DEV_INTERRUPTS_H
#define APOO_ARCHS_RISCV64_ARCH_DEV_INTERRUPTS_H

#include "archs/common/arch/dev/interrupts.h"

#include "common/attributes.h"
#include "common/config.h"

#if !ENABLE_TSAN

#define enable_interrupts enable_interrupts_raw
#define disable_interrupts disable_interrupts_raw
#define save_and_disable_interrupts(full_sync) save_and_disable_interrupts_raw()
#define restore_interrupts(saved, full_sync) restore_interrupts_raw(saved)

#endif  // !ENABLE_TSAN

static inline ALWAYS_INLINE
void enable_interrupts_raw(void) {
  asm volatile ("csrsi sstatus, 0x2\n\t");
}

static inline ALWAYS_INLINE
void disable_interrupts_raw(void) {
  asm volatile ("csrci sstatus, 0x2\n\t");
}

static inline ALWAYS_INLINE
interrupt_state_t get_interrupts_state(void) {
  interrupt_state_t val;
  asm volatile(
      "csrr %0, sstatus\n\t"
      "andi %0, %0, 0x2\n\t"
      : "=r"(val));
  return val;
}

static inline ALWAYS_INLINE
int save_and_disable_interrupts_raw(void) ACQUIRE(INTERRUPT) {
  uint64_t x;
  asm volatile (
      "csrrci %0, sstatus, 0x2\n\t"
      "andi %0, %0, 0x2\n\t"
      : "=r"(x));
  _interrupt_noop_acquire();
  return x;
}

static inline ALWAYS_INLINE
void restore_interrupts_raw(interrupt_state_t saved) RELEASE(INTERRUPT) {
  if (saved) {
    asm volatile ("csrsi sstatus, 0x2\n\t");
  }
  _interrupt_noop_release();
}

// Software-triggered supervisor interrupts.

// Triggers a synchronous preemption if there are other threads waiting.
#define RSV_SOFTINT_PREEMPT 1

static inline ALWAYS_INLINE void rsv_raise_softint(int type) {
  asm volatile(
      "mv a0, %[type]\n\t"
      "csrsi sip, 0x2\n\t" ::[type] "r"(type));
}

#endif
