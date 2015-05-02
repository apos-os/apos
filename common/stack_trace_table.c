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

#include "common/config.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/interrupts.h"

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

static entry_t g_tracetbl[TRACETBL_ENTRIES];
static int g_tblsize = 0;

extern addr_t _int_handlers_start;
extern addr_t _int_handlers_end;

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

  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT_DBG(g_tblsize >= 0 && g_tblsize <= TRACETBL_ENTRIES);
  if (g_tblsize == TRACETBL_ENTRIES) {
    klogfm(KL_GENERAL, DEBUG, "Stack trace table full; dropping trace @");
    for (int i = 0; i < len; ++i)
      klogfm(KL_GENERAL, DEBUG, " %#" PRIxADDR, trace[i]);
    klogfm(KL_GENERAL, DEBUG, "\n");
    POP_INTERRUPTS();
    return -ENOMEM;
  }

  while (g_tracetbl[id].refcount > 0 && g_tracetbl[id].hash != trace_hash) {
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
    g_tracetbl[id].refcount++;
  }

  POP_INTERRUPTS();
  return id;
}

int tracetbl_get(trace_id_t id, addr_t* trace) {
  if (id < 0 || id >= TRACETBL_ENTRIES)
    return -EINVAL;

  PUSH_AND_DISABLE_INTERRUPTS();
  int result;
  if (g_tracetbl[id].len == 0) {
    result = -EINVAL;
  } else {
    result = g_tracetbl[id].len;
    for (int i = 0; i < result; ++i)
      trace[i] = g_tracetbl[id].trace[i];
  }
  POP_INTERRUPTS();
  return result;
}

void tracetbl_unref(trace_id_t id) {
  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(id >= 0 && id < TRACETBL_ENTRIES);
  KASSERT(g_tracetbl[id].refcount > 0);
  g_tracetbl[id].refcount--;
  if (g_tracetbl[id].refcount == 0)
    g_tblsize--;
  POP_INTERRUPTS();
}
