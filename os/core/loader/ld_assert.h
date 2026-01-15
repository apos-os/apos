// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_CORE_LOADER_LD_ASSERT_H
#define APOO_OS_CORE_LOADER_LD_ASSERT_H

#include "os/core/loader/ld_printf.h"  // IWYU pragma: keep

#define STR2(x) #x
#define STR(x) STR2(x)

#define KASSERT_MSG(cond, fmt, ...)                           \
  do {                                                        \
    if (!(cond)) {                                            \
      if (*fmt) {                                             \
        ld_printf(fmt, ##__VA_ARGS__);                        \
        ld_printf("\n");                                      \
      }                                                       \
      kassert_msg(0, "assertion failed: " #cond " (" __FILE__ \
                     ":" STR(__LINE__) ")\n");                \
    }                                                         \
  } while (0)

#define KASSERT(cond)                                         \
  do {                                                        \
    if (!(cond)) {                                            \
      kassert_msg(0, "assertion failed: " #cond " (" __FILE__ \
                     ":" STR(__LINE__) ")\n");                \
    }                                                         \
  } while (0)

// Calls die() if x is zero.
void kassert(int x);
void kassert_msg(int x, const char* msg);

#endif
