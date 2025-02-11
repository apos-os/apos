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
#include "common/math.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"

int ksleep(int ms) {
  kthread_queue_t q;
  kthread_queue_init(&q);

  const apos_ms_t start_time = get_time_ms();
  int wait_result = scheduler_wait_on_interruptable(&q, ms);
  KASSERT_DBG(wait_result == SWAIT_TIMEOUT || wait_result == SWAIT_INTERRUPTED);
  const apos_ms_t elapsed = get_time_ms() - start_time;
  int result = (wait_result == SWAIT_INTERRUPTED) ? max((ms - elapsed), 0U) : 0;
  return result;
}
