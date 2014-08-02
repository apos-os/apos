// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_ARCHS_I586_ARCH_DEV_INTERRUPTS_H
#define APOO_ARCHS_I586_ARCH_DEV_INTERRUPTS_H

#include <stdint.h>

#include "archs/common/arch/dev/interrupts.h"

#define IF_FLAG 0x200

static inline uint32_t get_interrupts_state(void) {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(saved_flags));
  return saved_flags & IF_FLAG;
}

static inline uint32_t save_and_disable_interrupts(void) {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      "cli\n\t"
      : "=r"(saved_flags));
  return saved_flags & IF_FLAG;
}

static inline void restore_interrupts(uint32_t saved) {
  uint32_t saved_flags;
  asm volatile (
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(saved_flags));
  if (saved) {
    asm volatile ("sti");
  }
}

#endif
