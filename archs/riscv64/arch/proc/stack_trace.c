// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "common/klog.h"
#include "memory/memory.h"
#include "proc/kthread-internal.h"

#define SIZE_OF_JUMP_INSTR 4

static int get_stack_trace_internal(addr_t fp, addr_t stack_base,
                                    addrdiff_t stack_len, addr_t* frames,
                                    int trace_len) {
  int cframe = 0;
  while (fp != 0x0 && cframe < trace_len) {
    if (fp % sizeof(addr_t) != 0) {
      klogf("Warning: misaligned frame pointer 0x%" PRIxADDR "\n", fp);
      break;
    }

    if (fp < stack_base || fp > stack_base + stack_len) {
      klogf("Warning: frame pointer left stack (fp = %" PRIxADDR
            " stack_base = %" PRIxADDR ")",
            fp, stack_base);
      break;
    }

    addr_t ra = *(addr_t*)(fp - sizeof(addr_t));
    const addr_t old_fp = *(addr_t*)(fp - 2 * sizeof(addr_t));

    // Subtract to get back to the call instruction.
    ra -= SIZE_OF_JUMP_INSTR;
    frames[cframe++] = ra;
    fp = old_fp;

    // If the return address is outside the kernel, stop.
    // TODO(aoates): consider validating --- should always be a particular
    // sentinel (except thread 0).
    if (ra < get_global_meminfo()->kernel_mapped.base ||
        ra > get_global_meminfo()->kernel_mapped.base +
                 get_global_meminfo()->kernel_mapped.len) {
      break;
    }
  }
  return cframe;
}

int get_stack_trace(addr_t* trace, int trace_len) {
  addr_t fp;
  asm volatile("mv %0, fp" : "=r"(fp));
  // If a stack trace is requested before we've initialized kthread, default to
  // the default thread stack.
  addr_t stack_base;
  addrdiff_t stack_len;
  if (kthread_current_thread()) {
    stack_base = (addr_t)kthread_current_thread()->stack;
    stack_len = kthread_current_thread()->stacklen;
  } else {
    stack_base = get_global_meminfo()->thread0_stack.base;
    stack_len = get_global_meminfo()->thread0_stack.len;
  }
  return get_stack_trace_internal(fp, stack_base, stack_len, trace, trace_len);
}

int get_stack_trace_for_thread(kthread_t thread, addr_t* trace, int trace_len) {
  addr_t fp = thread->context + 112;
  return get_stack_trace_internal(fp, (addr_t)thread->stack, thread->stacklen,
                                  trace, trace_len);
}
