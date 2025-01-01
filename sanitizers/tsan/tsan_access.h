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

#ifndef APOO_SANITIZERS_TSAN_TSAN_ACCESS_H
#define APOO_SANITIZERS_TSAN_TSAN_ACCESS_H

#include <stdbool.h>

#include "common/types.h"

typedef enum {
  TSAN_ACCESS_READ = 0,
  TSAN_ACCESS_WRITE = 1,
} tsan_access_type_t;

// Call to check an access from a hook.
bool tsan_check(addr_t pc, addr_t addr, uint8_t size, tsan_access_type_t type);

#endif
