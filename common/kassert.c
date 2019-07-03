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

#include "arch/common/die.h"
#include "arch/proc/stack_trace.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "memory/memory.h"

static bool g_dying = false;

void die(const char* msg) {
  if (g_dying) {
    klog_set_mode(KLOG_RAW_VIDEO);
  }
  g_dying = true;
  klog("PANIC: ");
  if (msg) {
    klog(msg);
    klog("\n");
  } else {
    klog("<unknown reason :(>\n");
  }

  const int kMaxStackFrames = 32;
  addr_t stack_trace[kMaxStackFrames];
  const int frames = get_stack_trace(stack_trace, kMaxStackFrames);

  klog("Stack trace: \n");
  for (int i = 0; i < frames; ++i) {
    klogf(" #%d %#" PRIxADDR "\n", i, stack_trace[i]);
  }

  arch_die();
}

void kassert(int x) {
  kassert_msg(x, 0);
}

void kassert_msg(int x, const char* msg) {
  if (!x) {
    die(msg);
  }
}
