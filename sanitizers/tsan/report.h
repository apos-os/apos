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

#ifndef APOO_SANITIZERS_TSAN_REPORT_H
#define APOO_SANITIZERS_TSAN_REPORT_H

#include "common/types.h"
#include "sanitizers/tsan/tsan_access.h"

// An access recorded or reported by TSAN.
typedef struct {
  // The address of the access.
  addr_t addr;

  // Type of access.
  tsan_access_type_t type;

  // Size of the access (in bytes).
  uint8_t size;

  // The code address (PC) where the access occurred, or zero if unknown.
  addr_t pc;
} tsan_access_t;

// A TSAN race that was detected.
typedef struct {
  // The access that triggered the race.
  tsan_access_t cur;

  // The previous access, which the current access raced with.
  tsan_access_t prev;
} tsan_race_t;

// A TSAN report.
typedef struct {
  tsan_race_t race;
} tsan_report_t;

#endif
