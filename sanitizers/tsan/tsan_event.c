// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "sanitizers/tsan/tsan_event.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "dev/interrupts.h"
#include "sanitizers/tsan/report.h"
#include "sanitizers/tsan/tsan_access.h"
#include "vfs/vnode.h"

void tsan_event_init(tsan_event_log_t* log) {
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->pos = 0;
  log->len = 0;
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_log_access(tsan_event_log_t* log, addr_t pc, addr_t addr, int size,
                     tsan_access_type_t type) {
  tsan_event_t event;
  event.type = TSAN_EVENT_ACCESS;
  event.is_read = (type == TSAN_ACCESS_READ);
  event.addr = addr;
  event.pc = pc;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  int entries = 1;
  if (size <= 8) {
    event.size = size;
  } else {
    event.size = 0;

    log->events[log->pos] = (tsan_event_t){0};
    log->events[log->pos].pc = size;
    log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
    entries++;
  }

  log->events[log->pos] = event;
  log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
  if (log->len < TSAN_EVENT_LOG_LEN) {
    log->len += entries;
  }
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_log_func_entry(tsan_event_log_t* log, addr_t pc) {
  tsan_event_t event;
  event.type = TSAN_EVENT_FUNC;
  event.pc = pc;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->events[log->pos] = event;
  log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
  if (log->len < TSAN_EVENT_LOG_LEN) {
    log->len++;
  }
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_log_func_exit(tsan_event_log_t* log) {
  tsan_event_t event;
  event.type = TSAN_EVENT_FUNC;
  event.pc = 0;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->events[log->pos] = event;
  log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
  if (log->len < TSAN_EVENT_LOG_LEN) {
    log->len++;
  }
  POP_INTERRUPTS_NO_TSAN();
}

int tsan_find_access(const tsan_event_log_t* log, addr_t addr, int size,
                     tsan_access_type_t type, tsan_access_t* result) {
  KASSERT(TSAN_ADDR_MAX_BITS == 40);  // Or must adjust constants.
  const uint64_t upper_bits = 0xffffff0000000000UL;
  for (int i = 0; i < TSAN_MAX_STACK_LEN; ++i) {
    result->trace[i] = 0;
  }
  result->addr = addr;
  result->size = size;
  result->type = type;

  if (!log) return 0;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  // First find the access.
  int access_idx = -1;
  int stack_idx = 0;

  for (int i = 1; i <= log->len; ++i) {
    int idx = (log->pos - i + TSAN_EVENT_LOG_LEN) % TSAN_EVENT_LOG_LEN;
    if (log->events[idx].type != TSAN_EVENT_ACCESS) continue;

    int log_size = log->events[idx].size;
    if (log_size == 0) {
      int ext_idx =
          (log->pos - i - 1 + TSAN_EVENT_LOG_LEN) % TSAN_EVENT_LOG_LEN;
      KASSERT(log->events[ext_idx].type == TSAN_EVENT_ACCESS);
      KASSERT(log->events[ext_idx].addr == 0);
      log_size = log->events[ext_idx].pc;
      i++;  // Skip the next entry (the extended one).
    }

    bool is_read = (type == TSAN_ACCESS_READ);
    if (log->events[idx].is_read != is_read) continue;

    // The shadow access will always be the same size or smaller than event
    // size, and start at the same address or higher.
    addr_t masked_addr = addr & ~upper_bits;
    if (log_size < size) continue;
    if (log->events[idx].addr > masked_addr) continue;
    if (log->events[idx].addr + log_size < masked_addr + size)
      continue;

    // Update the result with more accurate data.
    result->addr = log->events[idx].addr | upper_bits;
    result->size = log_size;

    result->trace[stack_idx++] = log->events[idx].pc | upper_bits;
    access_idx = i;  // Note --- may be the extended entry.
    break;
  }

  if (access_idx < 0) {
    klogf("Unable to find TSAN access in log for address %" PRIxADDR "\n",
          addr);
    POP_INTERRUPTS_NO_TSAN();
    return -EINVAL;
  }

  // Now reconstruct the stack trace.
  int exit_counter = 0;
  for (int i = access_idx; i <= TSAN_EVENT_LOG_LEN; ++i) {
    int idx = (log->pos - i + TSAN_EVENT_LOG_LEN) % TSAN_EVENT_LOG_LEN;
    if (log->events[idx].type != TSAN_EVENT_FUNC) continue;

    if (log->events[idx].pc == 0) {
      exit_counter++;
    } else if (exit_counter > 0) {
      exit_counter--;
    } else {
      result->trace[stack_idx] = log->events[idx].pc | upper_bits;
      stack_idx++;

      if (stack_idx >= TSAN_MAX_STACK_LEN) {
        klogf("TSAN truncated stack trace after %d entries\n", stack_idx);
        break;
      }
    }
  }
  POP_INTERRUPTS_NO_TSAN();
  return 0;
}
