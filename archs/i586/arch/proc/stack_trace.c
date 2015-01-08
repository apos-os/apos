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

#include "common/klog.h"
#include "common/kstring.h"
#include "memory/memory.h"

#define CALL_INSTRUCTION_SIZE 2

void print_stack_trace(void) {
  _Static_assert(sizeof(addr_t) == sizeof(uint32_t), "not 32-bit");
  const int kMaxFrames = 32;
  addr_t frames[kMaxFrames];
  int cframe = 0;

  // Get our current %ebp.
  addr_t ebp;
  asm volatile (
      "mov %%ebp, %0"
      : "=g"(ebp));

  while (ebp != 0x0) {
    const addr_t old_ebp = *(addr_t*)ebp;
    if (old_ebp == 0) break;

    // Subtract 2 to get back to the call instruction.
    const addr_t return_addr =
        *(addr_t*)(ebp + sizeof(addr_t)) - CALL_INSTRUCTION_SIZE;
    if (cframe >= kMaxFrames) break;

    frames[cframe++] = return_addr;
    ebp = old_ebp;

    // If we're about to go before the start of a thread (0xDEADxxxx), or into
    // pre-VM addresses, stop.
    if ((return_addr & 0xFFFF0000) == 0xDEAD0000 ||
        return_addr < get_global_meminfo()->mapped_start) {
      break;
    }
  }

  for (int i = 0; i < cframe; ++i) {
    klogf(" #%d 0x%x\n", i, frames[i]);
  }
}
