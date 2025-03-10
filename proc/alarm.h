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

#ifndef APOO_PROC_ALARM_H
#define APOO_PROC_ALARM_H

#include <stdint.h>

#include "proc/defint_timer.h"

// An alarm in a process.  Each process has exactly one alarm.
typedef struct {
  apos_ms_t deadline_ms;
  defint_timer_t timer;
} proc_alarm_t;

// Initialize an alarm in a process.
void proc_alarm_init(proc_alarm_t* alarm);

// Register an alarm to trigger in |ms|, as per alarm(2).
unsigned int proc_alarm_ms(unsigned int ms);

#endif
