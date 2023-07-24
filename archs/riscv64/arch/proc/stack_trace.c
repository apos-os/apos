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
#include "proc/kthread-internal.h"

#define SIZE_OF_JUMP_INSTR 4

static int get_stack_trace_internal(addr_t fp, addr_t stack_top, addr_t* frames,
                                    int trace_len) {
  int cframe = 0;
  while (fp != 0x0 && cframe < trace_len) {
    if (fp % sizeof(addr_t) != 0) {
      klogf("Warning: aligned frame pointer 0x%" PRIxADDR "\n", fp);
      break;
    }

    if (fp < stack_top || fp > stack_top + KTHREAD_STACK_SIZE) {
      klogf("Warning: frame pointer left stack (fp = %" PRIxADDR
            " stack_top = %" PRIxADDR ")",
            fp, stack_top);
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
    if (ra < get_global_meminfo()->mapped_start ||
        ra > get_global_meminfo()->mapped_end) {
      break;
    }
  }
  return cframe;
}

int get_stack_trace(addr_t* trace, int trace_len) {
  addr_t fp;
  asm volatile("mv %0, fp" : "=r"(fp));
  return get_stack_trace_internal(fp, (addr_t)kthread_current_thread()->stack,
                                  trace, trace_len);
}

int get_stack_trace_for_thread(kthread_t thread, addr_t* trace, int trace_len) {
  addr_t fp = thread->context + 112;
  return get_stack_trace_internal(fp, (addr_t)thread->stack, trace, trace_len);
}
