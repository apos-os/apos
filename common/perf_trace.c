// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "common/perf_trace.h"

#include "arch/dev/timer.h"
#include "arch/proc/stack_trace.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/math.h"
#include "common/stack_trace_table.h"
#include "memory/kmalloc.h"
#include "proc/spinlock.h"

typedef struct {
  htbl_t traces;  // trace_id_t -> trace_t*
  kspinlock_intsafe_t lock;
  bool init;
  bool enabled;
  int total_stack_entries;
} perftrace_tbl_t;

#define PERFTRACE_TBL_INIT \
  { HTBL_STATIC_DECL, KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC, false, false, 0 }

static perftrace_tbl_t g_ptbl = PERFTRACE_TBL_INIT;

typedef struct {
  int count;
  uint64_t elapsed_time;
} trace_entry_t;

void perftrace_init(void) {
  KASSERT(!g_ptbl.init);
  htbl_init(&g_ptbl.traces, 10);
  g_ptbl.total_stack_entries = 0;
  g_ptbl.init = true;
}

void perftrace_enable(void) {
  kspin_lock_int(&g_ptbl.lock);
  g_ptbl.enabled = true;
  kspin_unlock_int(&g_ptbl.lock);
}

void perftrace_disable(void) {
  kspin_lock_int(&g_ptbl.lock);
  g_ptbl.enabled = false;
  kspin_unlock_int(&g_ptbl.lock);
}

void perftrace_log(uint64_t elapsed_time, int max_stack_frames) {
  // TODO(SMP): this should be an atomic operation.
  if (!g_ptbl.init || !g_ptbl.enabled) {
    return;
  }

  // Increment the counter at least once --- while not accurate, this ensures
  // that we will have at least a proportional sample count on architectures
  // with too long of a timer resolution.
  elapsed_time = max(elapsed_time, 1U);

  addr_t stack_trace[32];
  int stack_trace_len = get_stack_trace(stack_trace, 32);
  KASSERT_DBG(stack_trace_len > 3);
  // Exclude this function from the call stack.
  stack_trace_len--;
  if (max_stack_frames > 0) {
    stack_trace_len = min(stack_trace_len, max_stack_frames);
  }
  const trace_id_t stack_trace_id =
      tracetbl_put(stack_trace + 1, stack_trace_len);
  KASSERT(stack_trace_id >= 0);

  kspin_lock_int(&g_ptbl.lock);
  void* val;
  if (htbl_get(&g_ptbl.traces, stack_trace_id, &val) == 0) {
    trace_entry_t* entry = (trace_entry_t*)val;
    entry->count++;
    entry->elapsed_time += elapsed_time;
  } else {
    trace_entry_t* entry = KMALLOC(trace_entry_t);
    entry->count = 1;
    entry->elapsed_time = elapsed_time;
    htbl_put(&g_ptbl.traces, stack_trace_id, entry);
    g_ptbl.total_stack_entries += stack_trace_len;
  }
  kspin_unlock_int(&g_ptbl.lock);
}

typedef struct {
  uint64_t* buf;
  uint32_t sample_divisor;
} perftrace_iter_args_t;

static void perftrace_iter(void* arg, uint32_t key, void* val) {
  perftrace_iter_args_t* args = (perftrace_iter_args_t*)arg;
  trace_id_t trace_id = (trace_id_t)key;
  const trace_entry_t* entry = (trace_entry_t*)val;
  // TODO(aoates): do something more elegant than this.  Without this cast, on
  // i586 we get perf_trace.c:97: undefined reference to `__udivdi3'
#if ARCH_IS_64_BIT
  *args->buf = entry->elapsed_time / args->sample_divisor;
#else
  *args->buf = (uint32_t)entry->elapsed_time / args->sample_divisor;
#endif
  args->buf++;
  addr_t stack_trace[TRACETBL_MAX_TRACE_LEN];
  int len = tracetbl_get(trace_id, stack_trace);
  KASSERT(len > 0);
  *args->buf = len;
  args->buf++;
  for (int i = 0; i < len; ++i) {
    *args->buf = stack_trace[i];
    args->buf++;
  }
}

#define MICROS_PER_SEC 1000000

ssize_t perftrace_dump(uint8_t** buf_out) {
  kspin_lock_int(&g_ptbl.lock);
  KASSERT(g_ptbl.init);

  // First, calculate our buffer size.
  size_t bufsize_words = 5 /* header */ +
      2 * htbl_size(&g_ptbl.traces)  /* each entry header */ +
      g_ptbl.total_stack_entries +
      3 /* trailer */;
  // TODO(aoates): make this work for 32-bit architectures.
  size_t bufsize = bufsize_words * sizeof(uint64_t);
  perftrace_iter_args_t a;
  a.buf = (uint64_t*)kmalloc(bufsize);
  uint64_t* buf_orig = a.buf;
  *buf_out = (uint8_t*)a.buf;

  uint32_t arch_freq = arch_real_timer_freq();
  uint64_t out_freq;
  if (arch_freq > MICROS_PER_SEC) {
    a.sample_divisor = arch_freq / MICROS_PER_SEC;
    out_freq = 1;
  } else {
    a.sample_divisor = 1;
    out_freq = MICROS_PER_SEC / arch_freq;
  }

  a.buf[0] = 0;
  a.buf[1] = 3;
  a.buf[2] = 0;
  a.buf[3] = out_freq;
  a.buf[4] = 0;
  a.buf += 5;

  htbl_iterate(&g_ptbl.traces, &perftrace_iter, &a);

  a.buf[0] = 0;
  a.buf[1] = 1;
  a.buf[2] = 0;
  a.buf += 3;

  KASSERT((size_t)(a.buf - buf_orig) <= bufsize_words);
  kspin_unlock_int(&g_ptbl.lock);
  return (a.buf - buf_orig) * sizeof(uint64_t);
}
