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

#include <stdint.h>

#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/irq.h"
#include "dev/timer.h"

typedef struct {
  uint32_t counter;
  uint32_t period_slices;  // the timers period in units of timeslices
  timer_handler_t handler;
} timer_t;

static timer_t timers[KMAX_TIMERS];
static uint32_t timer_idx = 0;  // Points to the next free timer.
static uint32_t time_ms = 0;  // Time (in ms) since timer initialization.

static void internal_timer_handler() {
  time_ms += KTIMESLICE_MS;
  for (uint32_t i = 0; i < timer_idx; ++i) {
    if (timers[i].counter == 0) {
      timers[i].counter = timers[i].period_slices;
      timers[i].handler();
    }

    timers[i].counter--;
  }
}

void timer_init() {
  // Inintialize the timer hardware.
  outb(0x43, 0x36);
  uint16_t freq = 1000 / KTIMESLICE_MS;
  uint16_t divisor = 1193180 / freq;
  uint8_t low = (uint8_t)(divisor & 0xFF);
  uint8_t high = (uint8_t)((divisor >> 8) & 0xFF);
  outb(0x40, low);
  outb(0x40, high);

  register_irq_handler(IRQ0, &internal_timer_handler);

  timer_idx = 0;
}

int register_timer_callback(uint32_t period, timer_handler_t cb) {
  if (timer_idx >= KMAX_TIMERS) {
    return 0;
  }
  uint32_t idx = timer_idx++;
  timers[idx].period_slices = period / KTIMESLICE_MS;
  if (timers[idx].period_slices == 0) {
    timers[idx].period_slices = 1;
  }
  timers[idx].counter = timers[idx].period_slices;
  timers[idx].handler = cb;
  return 1;
}

uint32_t get_time_ms() {
  return time_ms;
}
