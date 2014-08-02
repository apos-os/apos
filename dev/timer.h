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

// Interrupt-driven kernel timer.
#ifndef APOO_TIMER_H
#define APOO_TIMER_H

#include <stdint.h>

#define KMAX_TIMERS 10
#define KTIMESLICE_MS 10

// Initialize the timer.  Must be called AFTER interrupts/IRQs are enabled.
void timer_init(void);

typedef void (*timer_handler_t)(void*);

typedef void* timer_handle_t;
#define TIMER_HANDLE_NONE 0x0

// Register a function to be called every X ms, where X must be an even multiple
// of the timeslice size.  Returns 0 on success, or -errno on error.
//
// If limit is positive, the timer will only be triggered that many times.  If
// limit is 0, the timer will trigger indefinitely.
//
// NOTE: the handler will be called in an interrupt context, so it should be
// fast, careful, and not block!
//
// NOTE 2: there are a limited number of timers that can be installed
// (KMAX_TIMERS).  register_timer_callback will return -ENOMEM if you've
// exceeded this limit.
//
// TODO(aoates): convert remaining users of this to use register_event_timer()
// instead.
int register_timer_callback(uint32_t period_ms, int limit,
                            timer_handler_t cb, void* arg);

// Register a one-shot time that calls the given handler at the given deadline
// (as determined by get_time_ms()).
//
// Prefer this to registering a one-shot timer with register_timer_callback, as
// there can be an unbounded number of one-shot events.
//
// If |handle| is non-NULL, it will be set to a handle that can be used to
// cancel the timer before it fires.
//
// REQUIRES: kmalloc_init()
int register_event_timer(uint32_t deadline_ms, timer_handler_t cb, void* arg,
                         timer_handle_t* handle);

// Cancel a timer created with register_event_timer.
//
// NOTE: The timer must not have fired already.  This means the general usage
// model should be,
//   PUSH_AND_DISABLE_INTERRUPTS();
//   if (!timer_fired) cancel_event_timer(handle);
//   POP_INTERRUPTS()
void cancel_event_timer(timer_handle_t handle);

// Cancel all event timers, for tests.
void cancel_all_event_timers_for_tests(void);

// Return the approximate time since timer initialization, in ms.
uint32_t get_time_ms(void);

#endif
