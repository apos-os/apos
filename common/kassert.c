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
#include "dev/interrupts.h"
#include "memory/memory.h"
#include "proc/kthread-internal.h"

static bool g_dying = false;
const int kMaxStackFrames = 32;

static void do_print_stack(kthread_t thread, void* arg) {
  if (thread == kthread_current_thread()) return;

  addr_t* stack_trace = (addr_t*)arg;
  const int frames =
      get_stack_trace_for_thread(thread, stack_trace, kMaxStackFrames);

  klogf("Thread %d:\n", thread->id);
  print_stack_trace(stack_trace, frames);
}

void die(const char* msg) {
  disable_interrupts();

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

  addr_t stack_trace[kMaxStackFrames];
  kthread_run_on_all(&do_print_stack, stack_trace);

  const int frames = get_stack_trace(stack_trace, kMaxStackFrames);
  klogf("Thread %d (crashing):\n", kthread_current_thread()->id);
  print_stack_trace(stack_trace, frames);

  // Print the panic again for ease of reading the logs.
  klogf("PANIC: %s\n", msg ? msg : "<unknown>");
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
