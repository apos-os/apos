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
#include "arch/dev/timer.h"

#include <stdint.h>

#include "arch/common/io.h"
#include "arch/dev/irq.h"
#include "dev/timer.h"

void arch_init_timer(apos_ms_t period_ms, void (*cb)(void*), void* cbarg) {
  // Inintialize the timer hardware.
  outb(0x43, 0x36);
  uint16_t freq = 1000 / period_ms;
  uint16_t divisor = 1193180 / freq;
  uint8_t low = (uint8_t)(divisor & 0xFF);
  uint8_t high = (uint8_t)((divisor >> 8) & 0xFF);
  outb(0x40, low);
  outb(0x40, high);

  register_irq_handler(IRQ0, cb, cbarg);
}

uint64_t arch_real_timer(void) {
  // TODO(aoates): use a more granular performance counter.
  return get_time_ms();
}

uint32_t arch_real_timer_freq(void) {
  return 1000;
}
