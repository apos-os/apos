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

#include "common/kassert.h"

#include "common/klog.h"
#include "common/kstring.h"
#include "memory/memory.h"

static void print_stack_trace(void) {
  const int kMaxFrames = 32;
  uint32_t frames[kMaxFrames];
  int cframe = 0;

  // Get our current %ebp.
  uint32_t ebp;
  asm volatile (
      "mov %%ebp, %0"
      : "=g"(ebp));

  while (ebp != 0x0) {
    const uint32_t old_ebp = *(uint32_t*)ebp;
    // Subtract 2 to get back to the call instruction.
    const uint32_t return_addr = *(uint32_t*)(ebp + 4) - 2;
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

void die(const char* msg) {
  klog("PANIC: ");
  if (msg) {
    klog(msg);
    klog("\n");
  } else {
    klog("<unknown reason :(>\n");
  }
  klog("Stack trace: \n");
  print_stack_trace();
  asm volatile (
      "cli\n\t"
      "hlt\n\t");
}

void kassert(int x) {
  kassert_msg(x, 0);
}

void kassert_msg(int x, const char* msg) {
  if (!x) {
    die(msg);
  }
}
