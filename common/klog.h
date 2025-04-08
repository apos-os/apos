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

// Logging utilities for logging in the kernel.
// See also klog_control.h for control functions.
#ifndef APOO_KLOG_H
#define APOO_KLOG_H

#include "common/types.h"
#include "common/klog_modules.h"

// Log levels.  There is a global minimum log level, as well as per-module
// minimum log levels.  A message will only be printed if its log level is less
// than either of those minimums.
typedef enum {
  LOG_NONE = 0,

  FATAL,
  DFATAL,
  ERROR,
  WARNING,
  INFO,
  DEBUG,
  DEBUG2,
  DEBUG3,

  LOG_ALL,
} klog_level_t;

// Log the given string for the KL_GENERAL module.  Deprecated.
// TODO(aoates): update all call sites for these functions to use klogfm().
void klog(const char* s);
void klogf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// Log the given string with the given module and log level.
void klogm(klog_module_t module, klog_level_t level, const char* s);
void klogfm(klog_module_t module, klog_level_t level, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));

// Returns 1 if logging is enabled for the given module and level.
int klog_enabled(klog_module_t module, klog_level_t level);

void print_stack_trace(addr_t* stack_trace, int frames);

#endif
