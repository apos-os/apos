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

#ifndef APOO_ARCHS_COMMON_ARCH_DEV_INTERRUPTS_H
#define APOO_ARCHS_COMMON_ARCH_DEV_INTERRUPTS_H

#include <stdbool.h>
#include <stdint.h>

typedef int interrupt_state_t;

void interrupts_init(void);

void enable_interrupts(void);
void disable_interrupts(void);

// Disable interrupts and return the previous (pre-disabling) state.
// If |full_sync| is true, this should be considered a full synchronization
// event between all threads, not just the current thread and interrupt
// handlers.
interrupt_state_t save_and_disable_interrupts(bool full_sync);

// Restore interrupt state (given the return value of
// save_and_disable_interrupts).
void restore_interrupts(interrupt_state_t saved, bool full_sync);

// Return the current IF flag state (as per save_and_disable_interrupts).
interrupt_state_t get_interrupts_state(void);

#endif
