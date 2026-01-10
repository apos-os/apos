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

#ifndef APOO_OS_CORE_LOADER_LD_PRINTF_H
#define APOO_OS_CORE_LOADER_LD_PRINTF_H

#include "common/kprintf.h"  // IWYU pragma: export

// Similar to printf() --- prints the given formatted string to stdout.
int ld_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

int ld_log_level(void);
// Log at a particular debug level.
#define LOG(_level, _fmt, ...)      \
  do {                              \
    if (ld_log_level() >= _level) { \
      ld_printf(_fmt, __VA_ARGS__); \
    }                               \
  } while (0)

#endif
