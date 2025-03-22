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

#include "common/stack_trace_table.h"

#include <limits.h>

#include "common/config.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "proc/spinlock.h"

#if ENABLE_KMALLOC_HEAP_PROFILE
#define TRACETBL_ENTRIES 750
#else
#define TRACETBL_ENTRIES 1
#endif

typedef struct {
  unsigned char len;
  short refcount;
  uint32_t hash;
  addr_t trace[TRACETBL_MAX_TRACE_LEN];
} entry_t;

#define REFCOUNT_MAX SHRT_MAX

static entry_t g_tracetbl[TRACETBL_ENTRIES];
static int g_tblsize = 0;
static kspinlock_intsafe_t g_tracetbl_mu = KSPINLOCK_INTERRUPT_SAFE_INIT_STATIC;

extern addr_t _int_handlers_start;
extern addr_t _int_handlers_end;

static inline ALWAYS_INLINE interrupt_state_t _tracetbl_lock(void)
    ACQUIRE(g_tracetbl_mu) NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    kspin_lock_int(&g_tracetbl_mu);
    return 0;
  } else {
    return save_and_disable_interrupts(true);
  }
}

static inline ALWAYS_INLINE void _tracetbl_unlock(interrupt_state_t s)
    RELEASE(g_tracetbl_mu) NO_THREAD_SAFETY_ANALYSIS {
  if (kthread_current_thread()) {
    kspin_unlock_int(&g_tracetbl_mu);
  } else {
    restore_interrupts(s, true);
  }
}

#define TRACETBL_LOCK() interrupt_state_t _SAVED_INTERRUPTS = _tracetbl_lock()
#define TRACETBL_UNLOCK() _tracetbl_unlock(_SAVED_INTERRUPTS);

trace_id_t tracetbl_put(const addr_t* trace, int len) {
  len = min(len, TRACETBL_MAX_TRACE_LEN);

  // Truncate the stack trace at any interrupt handlers, to prevent
  // combinatorial explosion of stack traces.
  for (int i = 0; i < len; ++i) {
    if (trace[i] >= (addr_t)&_int_handlers_start &&
        trace[i] < (addr_t)&_int_handlers_end) {
      len = i + 1;
      break;
    }
  }

  const uint32_t trace_hash = fnv_hash_array(trace, sizeof(addr_t) * len);
  int id = trace_hash % TRACETBL_ENTRIES;

  TRACETBL_LOCK();
  KASSERT_DBG(g_tblsize >= 0 && g_tblsize <= TRACETBL_ENTRIES);
  if (g_tblsize == TRACETBL_ENTRIES) {
    klogfm(KL_GENERAL, DEBUG, "Stack trace table full; dropping trace @");
    for (int i = 0; i < len; ++i)
      klogfm(KL_GENERAL, DEBUG, " %#" PRIxADDR, trace[i]);
    klogfm(KL_GENERAL, DEBUG, "\n");
    TRACETBL_UNLOCK();
    return -ENOMEM;
  }

  while (g_tracetbl[id].refcount > 0 &&
         (g_tracetbl[id].hash != trace_hash || g_tracetbl[id].len != len)) {
    id = (id + 1) % TRACETBL_ENTRIES;
  }

  if (g_tracetbl[id].refcount == 0) {
    g_tracetbl[id].refcount = 1;
    g_tracetbl[id].len = len;
    g_tracetbl[id].hash = trace_hash;
    for (int i = 0; i < len; ++i) g_tracetbl[id].trace[i] = trace[i];
    g_tblsize++;
  } else {
    KASSERT_DBG(g_tracetbl[id].len == len);
    KASSERT_DBG(kmemcmp(g_tracetbl[id].trace, trace, len) == 0);
    KASSERT(g_tracetbl[id].refcount < REFCOUNT_MAX);
    g_tracetbl[id].refcount++;
  }

  TRACETBL_UNLOCK();
  return id;
}

int tracetbl_get(trace_id_t id, addr_t* trace) {
  if (id < 0 || id >= TRACETBL_ENTRIES)
    return -EINVAL;

  TRACETBL_LOCK();
  int result;
  if (g_tracetbl[id].len == 0) {
    result = -EINVAL;
  } else {
    result = g_tracetbl[id].len;
    for (int i = 0; i < result; ++i)
      trace[i] = g_tracetbl[id].trace[i];
  }
  TRACETBL_UNLOCK();
  return result;
}

void tracetbl_unref(trace_id_t id) {
  TRACETBL_LOCK();
  KASSERT(id >= 0 && id < TRACETBL_ENTRIES);
  KASSERT(g_tracetbl[id].refcount > 0);
  g_tracetbl[id].refcount--;
  if (g_tracetbl[id].refcount == 0)
    g_tblsize--;
  TRACETBL_UNLOCK();
}
