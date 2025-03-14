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

// Driver for the real-time clock next to the CMOS chip.
#ifndef APOO_DEV_RTC_PC_RTC_H
#define APOO_DEV_RTC_PC_RTC_H

#include <stdint.h>

// A (decoded) time value from the RTC.
typedef struct {
  uint8_t seconds;
  uint8_t minutes;
  uint8_t hours;  // 24-hour format.
  uint8_t day_of_month;
  uint8_t month;
  uint8_t year;
  uint8_t century;

  // Used internally.
  uint8_t status_a;
  uint8_t status_b;
} pcrtc_time_t;

// Reads and decodes the current time from the RTC.  Returns zero on error.
int pcrtc_read_time(pcrtc_time_t* time);

// Stringify the given time into a buffer.
void pcrtc_to_string(char* buf, pcrtc_time_t* t);

#endif
