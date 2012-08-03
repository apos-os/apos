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

#include "common/errno.h"
#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/irq.h"
#include "dev/timer.h"

typedef struct {
  uint32_t counter;
  uint32_t period_slices;  // the timers period in units of timeslices
  timer_handler_t handler;
  void* handler_arg;
  int free;
  int prev;  // Index of the prev timer in the linked list, or -1.
  int next;
} timer_t;

// This is actually a linked list of timers, with static allocation to prevent a
// dependency on kmalloc or slab_alloc.
static timer_t timers[KMAX_TIMERS];
static uint32_t num_timers = 0;
static uint32_t time_ms = 0;  // Time (in ms) since timer initialization.
static int list_head = -1;  // Head (idx) of linked list.

static void internal_timer_handler() {
  time_ms += KTIMESLICE_MS;
  int idx = list_head;
  while (idx >= 0) {
    if (timers[idx].counter == 0) {
      timers[idx].counter = timers[idx].period_slices;
      timers[idx].handler(timers[idx].handler_arg);
    }

    timers[idx].counter--;
    idx = timers[idx].next;
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

  for (int i = 0; i < KMAX_TIMERS; ++i) {
    timers[i].free = 1;
  }
  num_timers = 0;
}

int register_timer_callback(uint32_t period, timer_handler_t cb, void* arg) {
  if (num_timers >= KMAX_TIMERS) {
    return -ENOMEM;
  }
  // Find a free slot.
  uint32_t idx;
  for (idx = 0; idx < KMAX_TIMERS; ++idx) {
    if (timers[idx].free) {
      break;
    }
  }
  KASSERT(idx < KMAX_TIMERS);
  num_timers++;

  // Add to front of the list.
  timers[idx].free = 0;
  timers[idx].prev = -1;
  timers[idx].next = list_head;
  if (list_head >= 0) {
    KASSERT(timers[list_head].prev == -1);
    timers[list_head].prev = idx;
  }
  list_head = idx;

  timers[idx].period_slices = period / KTIMESLICE_MS;
  if (timers[idx].period_slices == 0) {
    timers[idx].period_slices = 1;
  }
  timers[idx].counter = timers[idx].period_slices;
  timers[idx].handler = cb;
  timers[idx].handler_arg = arg;
  return 0;
}

uint32_t get_time_ms() {
  return time_ms;
}
