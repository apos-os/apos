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

#include "dev/faults.h"

#include "dev/interrupts.h"
#include "common/kassert.h"
#include "proc/process.h"
#include "proc/signal/signal.h"

static void fpe_handler(uint32_t interrupt, uint32_t error, int is_user) {
  if (!is_user) {
    die("floating point exception in kernel code");
  }

  proc_kill(proc_current()->id, SIGFPE);
}

void register_fault_handlers(void) {
  register_interrupt_handler(0, &fpe_handler);
  register_interrupt_handler(7, &fpe_handler);
  register_interrupt_handler(9, &fpe_handler);
  register_interrupt_handler(16, &fpe_handler);
  register_interrupt_handler(19, &fpe_handler);
}
