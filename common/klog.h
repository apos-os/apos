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

#include "dev/video/vterm.h"

// Log the given string.
void klog(const char* s);
void klogf(const char* fmt, ...);

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

#endif
