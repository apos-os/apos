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

#ifndef APOO_KASSERT_H
#define APOO_KASSERT_H

#include "common/debug.h"
#include "common/klog.h"

#define STR2(x) #x
#define STR(x) STR2(x)

#define KASSERT_MSG(cond, fmt, ...) do { \
  if (!(cond)) { \
    if (*fmt) { \
      klogf(fmt, ##__VA_ARGS__); \
      klog("\n"); \
    } \
    kassert_msg(0, "assertion failed: " #cond " (" __FILE__ ":" STR(__LINE__) ")\n"); \
  } \
} while(0)

#define KASSERT(cond) KASSERT_MSG(cond, "")

// Version of KASSERT that is a no-op in non-debug builds.
#if ENABLE_KERNEL_SAFETY_NETS
#define KASSERT_DBG(cond) KASSERT(cond)
#else
#define KASSERT_DBG(cond) do {} while (0)
#endif

// Kills the kernel, logging the given message first.
void die(const char* msg) __attribute__((noreturn));

// Calls die() if x is zero.
void kassert(int x);
void kassert_msg(int x, const char* msg);

#endif
