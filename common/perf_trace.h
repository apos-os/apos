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

// Utility for tracing performance.  Associates an event counter and cumulative
// sum with stack traces --- the cumulative sum is assumed to be an elapsed
// time.
#ifndef APOO_COMMON_PERF_TRACE_H
#define APOO_COMMON_PERF_TRACE_H

#include <stdint.h>

#include "common//types.h"

// Initialize perf tracing.  Any calls to perftrace_log() before this will be
// ignored.
void perftrace_init(void);

// Enable or disable perf tracing.
void perftrace_enable(void);
void perftrace_disable(void);

// Registers an event using the current stack trace.  Increments the event
// counter for the stack trace by 1, and the cumulative counter by elapsed time.
// |elapsed_time| should be in the units return by arch_real_timer().
//
// |trim_stack_frames| frames are removed from the bottom (inner-most) of the
// stack trace before recording.
//
// If non-negative, caps the number of stack trace entries if
// |max_stack_frames|.  This prevents combinatorial explosion of tracked stack
// frames with uninteresting upper frames.
void perftrace_log(uint64_t elapsed_time, int trim_stack_frames,
                   int max_stack_frames);

// As above, but for a manually-supplied stack trace.
void perftrace_log_trace(uint64_t elapsed_time, const addr_t* stack_trace,
                         int stack_trace_len);

// Dump the current perf trace data into a buffer.  Returns the number of bytes
// written, and sets |buf_out| to be the allocated buffer.  Dumps in the binary
// gperftools CPU trace format:
// https://gperftools.github.io/gperftools/cpuprofile-fileformat.html
ssize_t perftrace_dump(uint8_t** buf_out);

#endif
