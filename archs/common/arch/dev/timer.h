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

#ifndef APOO_ARCHS_COMMON_ARCH_DEV_TIMER_H
#define APOO_ARCHS_COMMON_ARCH_DEV_TIMER_H

#include <stdint.h>

#include "dev/timer.h"

// Initialize the basic system periodic timer with the given period.  The period
// may not be supported exactly.
void arch_init_timer(apos_ms_t period_ms, void (*cb)(void*), void* cbarg);

// Returns a cheap timer value in unspecified units.  The units must be
// proportional to real time elapsed (must not be variable).
uint64_t arch_real_timer(void);

// Returns the number of arch_real_timer() ticks per second.
uint32_t arch_real_timer_freq(void);

// Returns the number of profiler samples (if profiling is enabled) per second.
uint32_t arch_profile_samples_freq(void);

#endif
