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

#ifndef APOO_SANITIZERS_TSAN_TSAN_EVENT_H
#define APOO_SANITIZERS_TSAN_TSAN_EVENT_H

#include <stdbool.h>
#include <stdint.h>

#include "common/types.h"
#include "sanitizers/tsan/report.h"
#include "sanitizers/tsan/shadow_cell.h"
#include "sanitizers/tsan/tsan_access.h"

// All addresses and PC values are assumed to be at most this many bits.
#define TSAN_ADDR_MAX_BITS 40

#define TSAN_EVENT_LOG_LEN 10000

typedef enum {
  TSAN_EVENT_ACCESS = 0,
  TSAN_EVENT_FUNC,
} tsan_event_type_t;

// A recorded thread event.  This is not particularly optimized.
typedef struct {
  tsan_event_type_t type : 1;
  bool is_read : 1;
  uint8_t size : 3;                  // Access size - 1.
  addr_t addr : TSAN_ADDR_MAX_BITS;  // Address accessed, if an access.
  addr_t pc : TSAN_ADDR_MAX_BITS;    // PC value, or 0 if a function exit.
} tsan_event_t;

_Static_assert(sizeof(tsan_event_t) == 16, "bad tsan_event_t");

typedef struct {
  int pos;
  int len;
  tsan_event_t events[TSAN_EVENT_LOG_LEN];
} tsan_event_log_t;

void tsan_event_init(tsan_event_log_t* log);
void tsan_log_access(tsan_event_log_t* log, addr_t pc, addr_t addr, int size,
                     tsan_access_type_t type);
void tsan_log_func_entry(tsan_event_log_t* log, addr_t pc);
void tsan_log_func_exit(tsan_event_log_t* log);

// Given an access, find it in the event log and reconstruct a stack trace.  It
// looks for an overlapping but not identical access (as accesses may be split
// in shadow cells, but represented a single time in the event log).
int tsan_find_access(const tsan_event_log_t* log, addr_t addr, int size,
                     tsan_access_type_t type, tsan_access_t* result);

#endif
