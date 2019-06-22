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

// Code for registering and handling interrupts.
#ifndef APOO_INTERRUPTS_H
#define APOO_INTERRUPTS_H

#include <stdbool.h>
#include <stdint.h>

#include "arch/dev/interrupts.h"
#include "common/debug.h"

#if ENABLE_KERNEL_SAFETY_NETS
// If safety nets are enabled, verify that interrupts are popped properly after
// every PUSH_AND_DISABLE_INTERRUPTS.  This catches things like early returns
// that don't call POP_INTERRUPTS() when they should.
void _interrupts_unpopped_die(void);
static inline void _interrupts_cleanup_verify(interrupt_state_t* saved) {
  if (*saved != get_interrupts_state()) {
    _interrupts_unpopped_die();
  }
}
#endif  // ENABLE_KERNEL_SAFETY_NETS

// Macros to use the functions above (and ensure they're called in pairs).
#if ENABLE_KERNEL_SAFETY_NETS

#define PUSH_AND_DISABLE_INTERRUPTS() \
    interrupt_state_t _SAVED_INTERRUPTS \
      __attribute__((cleanup(_interrupts_cleanup_verify))) = \
      save_and_disable_interrupts()

#else  // ENABLE_KERNEL_SAFETY_NETS

#define PUSH_AND_DISABLE_INTERRUPTS() \
    interrupt_state_t _SAVED_INTERRUPTS = save_and_disable_interrupts()

#endif  // ENABLE_KERNEL_SAFETY_NETS

#define POP_INTERRUPTS() \
    restore_interrupts(_SAVED_INTERRUPTS);

// Returns true if interrupts are currently enabled.
static inline bool interrupts_enabled(void) {
  return get_interrupts_state() != 0;
}

#endif
