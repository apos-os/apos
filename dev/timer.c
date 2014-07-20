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

#include "arch/dev/irq.h"
#include "common/debug.h"
#include "common/errno.h"
#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/list.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"

// TODO(aoates): clean this up and unify the one-shot and recurring timers.

typedef struct {
  uint32_t counter;
  uint32_t period_slices;  // the timers period in units of timeslices
  timer_handler_t handler;
  void* handler_arg;
  int limit;

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

#if ENABLE_KERNEL_SAFETY_NETS
// Magic number in event_timer_t to indicate that it's valid.
const int kEventTimerValidMagic = 0x52187AB;
#endif

// For the event timers, we're allowed to used kmalloc(), so a true linked list
// of timers.
typedef struct {
  uint32_t deadline_ms;
  timer_handler_t handler;
  void* handler_arg;

  list_link_t link;

#if ENABLE_KERNEL_SAFETY_NETS
  int valid_magic;
#endif
} event_timer_t;

static list_t event_timers = LIST_INIT_STATIC;

static void internal_timer_handler(void* arg) {
  time_ms += KTIMESLICE_MS;
  int idx = list_head;
  while (idx >= 0) {
    if (timers[idx].counter == 0) {
      timers[idx].counter = timers[idx].period_slices;
      timers[idx].handler(timers[idx].handler_arg);

      if (timers[idx].limit > 0) {
        timers[idx].limit--;
        if (timers[idx].limit == 0) {
          timers[idx].free = 1;
          num_timers--;
          if (timers[idx].prev >= 0) {
            timers[timers[idx].prev].next = timers[idx].next;
          } else {
            list_head = timers[idx].next;
          }
          if (timers[idx].next >= 0) {
            timers[timers[idx].next].prev = timers[idx].prev;
          }
        }
      }
    }

    timers[idx].counter--;
    idx = timers[idx].next;
  }

  // Handle any pending event timers.
  while (!list_empty(&event_timers)) {
    event_timer_t* timer = container_of(event_timers.head, event_timer_t, link);
    if (timer->deadline_ms > time_ms) break;

    list_pop(&event_timers);
    timer->handler(timer->handler_arg);
#if ENABLE_KERNEL_SAFETY_NETS
    timer->valid_magic = 0;
#endif
    kfree(timer);
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

  register_irq_handler(IRQ0, &internal_timer_handler, 0x0);

  for (int i = 0; i < KMAX_TIMERS; ++i) {
    timers[i].free = 1;
  }
  num_timers = 0;
}

int register_timer_callback(uint32_t period, int limit,
                            timer_handler_t cb, void* arg) {
  // TODO(aoates): disable interrupts!
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
  timers[idx].limit = limit;
  return 0;
}

int register_event_timer(uint32_t deadline_ms, timer_handler_t cb, void* arg,
                         timer_handle_t* handle) {
  PUSH_AND_DISABLE_INTERRUPTS();

  event_timer_t* timer = (event_timer_t*)kmalloc(sizeof(event_timer_t));
  timer->deadline_ms = deadline_ms;
  timer->handler = cb;
  timer->handler_arg = arg;
  timer->link = LIST_LINK_INIT;
#if ENABLE_KERNEL_SAFETY_NETS
  timer->valid_magic = kEventTimerValidMagic;
#endif

  // Insert the timer in its spot in the priority queue.
  list_link_t* prev = 0x0;
  for (list_link_t* link = event_timers.head; link != 0x0;
       link = link->next) {
    event_timer_t* timer = container_of(link, event_timer_t, link);
    if (timer->deadline_ms >= deadline_ms) break;
    prev = link;
  }

  list_insert(&event_timers, prev, &timer->link);

  if (handle) {
    *handle = timer;
  }

  POP_INTERRUPTS();
  return 0;
}

void cancel_event_timer(timer_handle_t handle) {
  event_timer_t* timer = (event_timer_t*)handle;
#if ENABLE_KERNEL_SAFETY_NETS
  KASSERT(timer->valid_magic == kEventTimerValidMagic);
#endif

  PUSH_AND_DISABLE_INTERRUPTS();

  list_remove(&event_timers, &timer->link);
#if ENABLE_KERNEL_SAFETY_NETS
  timer->valid_magic = 0;
#endif
  kfree(timer);

  POP_INTERRUPTS();
}

uint32_t get_time_ms() {
  return time_ms;
}
