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

#include "arch/proc/stack_trace.h"

#include "common/config.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "memory/memory.h"
#include "proc/kthread-internal.h"

#define CALL_INSTRUCTION_SIZE 2

static int get_stack_trace_internal(addr_t ebp, addr_t* frames, int trace_len) {
  int cframe = 0;
  while (ebp != 0x0) {
    const addr_t old_ebp = *(addr_t*)ebp;
    if (old_ebp == 0) break;

    // Subtract 2 to get back to the call instruction.
    const addr_t return_addr =
        *(addr_t*)(ebp + sizeof(addr_t)) - CALL_INSTRUCTION_SIZE;
    if (cframe >= trace_len) break;

    frames[cframe++] = return_addr;
    ebp = old_ebp;

    // If we're about to go before the start of a thread (0xDEADxxxx), or into
    // pre-VM addresses, stop.
    if ((return_addr & 0xFFFF0000) == 0xDEAD0000 ||
        return_addr < get_global_meminfo()->mapped_start) {
      break;
    }
  }
  return cframe;
}

int get_stack_trace(addr_t* frames, int trace_len) {
  // Get our current %ebp.
  addr_t ebp;
#if ARCH == ARCH_i586
  asm volatile (
      "mov %%ebp, %0"
      : "=g"(ebp));
#elif ARCH == ARCH_x86_64
  asm volatile (
      "mov %%rbp, %0"
      : "=g"(ebp));
#else
#error WTF? Unknown x86 architecture.
#endif

  return get_stack_trace_internal(ebp, frames, trace_len);
}

int get_stack_trace_for_thread(kthread_t thread, addr_t* trace, int trace_len) {
  addr_t ebp = thread->context;
#if ARCH == ARCH_i586
  ebp += sizeof(addr_t) * 4;
#elif ARCH == ARCH_x86_64
  ebp += sizeof(addr_t) * 6;
#else
#error WTF? Unknown x86 architecture.
#endif
  return get_stack_trace_internal(ebp, trace, trace_len);
}
