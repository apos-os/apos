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

#ifndef APOO_ARCHS_COMMON_ARCH_PROC_STACK_TRACE_H
#define APOO_ARCHS_COMMON_ARCH_PROC_STACK_TRACE_H

#include <stddef.h>

#include "common/types.h"
#include "proc/kthread.h"

// Gather a stack trace from the current thread, storing it in the given buffer.
// Returns how many frames were store, or -error.
int get_stack_trace(addr_t* trace, int trace_len);

// As above, but get the stack trace for the given thread (which must not be
// running).
int get_stack_trace_for_thread(kthread_t thread, addr_t* trace, int trace_len);

#endif
