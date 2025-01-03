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

#include "dev/interrupts.h"
#include "sanitizers/tsan/tsan_access.h"

void tsan_event_init(tsan_event_log_t* log) {
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->pos = 0;
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_log_access(tsan_event_log_t* log, addr_t pc, addr_t addr, int size,
                     tsan_access_type_t type) {
  tsan_event_t event;
  event.type = TSAN_EVENT_ACCESS;
  event.is_read = (type == TSAN_ACCESS_READ);
  event.addr = addr;
  event.pc = pc;
  event.size = size;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->events[log->pos] = event;
  log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_log_func_entry(tsan_event_log_t* log, addr_t pc) {
  tsan_event_t event;
  event.type = TSAN_EVENT_FUNC;
  event.pc = pc;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->events[log->pos] = event;
  log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_log_func_exit(tsan_event_log_t* log) {
  tsan_event_t event;
  event.type = TSAN_EVENT_FUNC;
  event.pc = 0;

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  log->events[log->pos] = event;
  log->pos = (log->pos + 1) % TSAN_EVENT_LOG_LEN;
  POP_INTERRUPTS_NO_TSAN();
}
