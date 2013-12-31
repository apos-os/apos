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
#ifndef APOO_KLOG_H
#define APOO_KLOG_H

#include "common/klog_modules.h"
#include "dev/video/vterm.h"

// Log levels.  There is a global minimum log level, as well as per-module
// minimum log levels.  A message will only be printed if its log level is less
// than either of those minimums.
typedef enum {
  LOG_NONE = 0,

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
void klogf(const char* fmt, ...);

// Log the given string with the given module and log level.
void klogm(klog_module_t module, klog_level_t level, const char* s);
void klogfm(klog_module_t module, klog_level_t level, const char* fmt, ...);

// Different logging modes for the kernel, to be used at different stages in the
// boot process.  Defaults to KLOG_PARALLEL_PORT.  As soon as a vterm_t is
// available, KLOG_VTERM should be used (to play nice with other I/O).
#define KLOG_PARELLEL_PORT 1  // Only log to the parallel port.
#define KLOG_RAW_VIDEO 2      // Log by writing to raw video memory.
#define KLOG_VTERM 3          //

// Set the current logging mode.
void klog_set_mode(int mode);

// Set the vterm_t to be used with KLOG_VTERM.
void klog_set_vterm(vterm_t* t);

// Reads up to len bytes from the log history at the given offset into the
// buffer.  Returns the number of bytes read
int klog_read(int offset, void* buf, int len);

#endif
