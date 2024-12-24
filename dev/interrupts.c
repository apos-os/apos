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

#include <stdint.h>

#include "arch/dev/interrupts.h"
#include "common/kassert.h"
#include "dev/interrupts.h"
#include "proc/defint.h"

void restore_interrupts_and_defints(interrupt_state_t saved) {
  restore_interrupts(saved);
  // TODO(aoates): evaluate how to make defint scheduling more consistent to run
  // when threads switch, and get rid of this.
  if (saved) {
    defint_process_queued(/* force= */ false);
  }
}

void _interrupts_unpopped_die(void) {
  die("Interrupt state saved with PUSH_AND_DISABLE_INTERRUPTS(), but "
      "not popped before returning!");
}
