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

#include "archs/riscv64/internal/sbi.h"
#include "common/config.h"
#include "common/endian.h"
#include "common/kassert.h"
#include "common/perf_trace.h"
#include "dev/devicetree/devicetree.h"
#include "main/kernel.h"

// How many times per standard "tick" to attempt to profile
#if ENABLE_PROFILING
#define PROFILE_SAMPLE_MULT 1000
#else
#define PROFILE_SAMPLE_MULT 1
#endif

#define PROFILE_MAX_STACK_TRACE_LEN 32

static uint64_t g_rsv_timer_period = UINT32_MAX;
static void (*g_rsv_timer_cb)(void*);
static void* g_rsv_timer_cb_arg;

// TODO(aoates): support the ability for the arch to pass a more accurate clock
// value to the timer (rather than dead-reckoning from timer interrupts).

static uint32_t get_timebase_frequency(void) {
  // TODO(aoates): support getting timebase-frequency from cpu@X (if it varies
  // per-hart).
  const dt_property_t* prop =
      dt_get_nprop(get_boot_info()->dtree, "/cpus", "timebase-frequency");
  if (!prop) {
    die("Unable to find /cpus.timebase-frequency in FDT");
  }
  // TODO(aoates): this isn't fully spec-compliant; it can be an array or u64.
  if (prop->val_len != sizeof(uint32_t)) {
    die("Invalid timebase-frequency");
  }
  uint32_t tb_freq_hz = btoh32(*(uint32_t*)prop->val);
  return tb_freq_hz;
}

void rsv_timer_interrupt(void) {
  if (ENABLE_PROFILING) {
    // Remove 3 stack frames (this function, int_handler, and int_handler_asm).
    perftrace_log(1, 3, PROFILE_MAX_STACK_TRACE_LEN);
  }
  uint64_t time;
  asm volatile("rdtime %0" : "=r"(time)::);
  rsv64_sbi_set_timer(time + g_rsv_timer_period);
#if PROFILE_SAMPLE_MULT > 1
  static int counter = 1;
  if (--counter == 0) {
    g_rsv_timer_cb(g_rsv_timer_cb_arg);
    counter = PROFILE_SAMPLE_MULT;
  }
#else
  g_rsv_timer_cb(g_rsv_timer_cb_arg);
#endif
}

void arch_init_timer(apos_ms_t period_ms, void (*cb)(void*), void* cbarg) {
  g_rsv_timer_cb = cb;
  g_rsv_timer_cb_arg = cbarg;

  uint32_t tb_freq_hz = get_timebase_frequency();
  g_rsv_timer_period = period_ms * (tb_freq_hz / PROFILE_SAMPLE_MULT / 1000);

  rsv64_sbi_set_timer(0);
}

uint64_t arch_real_timer(void) {
  uint64_t time;
  asm volatile("rdtime %0" : "=r"(time)::);
  return time;
}

uint32_t arch_real_timer_freq(void) {
  return get_timebase_frequency();
}

uint32_t arch_profile_samples_freq(void) {
  return get_timebase_frequency() / g_rsv_timer_period;
}
