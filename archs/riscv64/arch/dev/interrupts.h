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

#include "common/config.h"

// The direct assembly implementations of these functions.  In non-TSAN mode,
// they should be run directly.
void enable_interrupts_raw(void);
void disable_interrupts_raw(void);
interrupt_state_t save_and_disable_interrupts_raw(void);
void restore_interrupts_raw(interrupt_state_t saved);

#if !ENABLE_TSAN

#define enable_interrupts enable_interrupts_raw
#define disable_interrupts disable_interrupts_raw
#define save_and_disable_interrupts save_and_disable_interrupts_raw
#define restore_interrupts restore_interrupts_raw

#endif  // !ENABLE_TSAN

#endif
