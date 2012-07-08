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

#include "common/io.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "dev/rtc.h"

#define CMOS_CMD_PORT  0x70
#define CMOS_DATA_PORT 0x71

#define NMI_DISABLE_BIT 0x80

// See http://www.bioscentral.com/misc/cmosmap.htm for details.
#define CMOS_REG_SECONDS       0x00
#define CMOS_REG_MINUTES       0x02
#define CMOS_REG_HOURS         0x04
#define CMOS_REG_WEEKDAY       0x06
#define CMOS_REG_DAY_OF_MONTH  0x07
#define CMOS_REG_MONTH         0x08
#define CMOS_REG_YEAR          0x09
#define CMOS_REG_CENTURY       0x32
#define CMOS_REG_STATUSA       0x0A
#define CMOS_REG_STATUSB       0x0B

#define CMOS_STATUSA_UPDATING   0x07
#define CMOS_STATUSB_24HOUR     0x02
#define CMOS_STATUSB_BINARY_FMT 0x04

static inline uint8_t rtc_read_reg(uint8_t reg) {
  outb(CMOS_CMD_PORT, reg);
  return inb(CMOS_DATA_PORT);
}

// Reads the raw (undecoded) RTC state a single time.
static void rtc_read_state(rtc_time_t* t) {
  // Wait until the current update (if any) is done.
  t->status_a = rtc_read_reg(CMOS_REG_STATUSA);
  while (!(t->status_a & CMOS_STATUSA_UPDATING)) {
    t->status_a = rtc_read_reg(CMOS_REG_STATUSA);
  }

  // TODO(aoates): verify the century bit exists before reading it.
  t->status_b = rtc_read_reg(CMOS_REG_STATUSB);
  t->seconds = rtc_read_reg(CMOS_REG_SECONDS);
  t->minutes = rtc_read_reg(CMOS_REG_MINUTES);
  t->hours = rtc_read_reg(CMOS_REG_HOURS);
  t->day_of_month = rtc_read_reg(CMOS_REG_DAY_OF_MONTH);
  t->month = rtc_read_reg(CMOS_REG_MONTH);
  t->year = rtc_read_reg(CMOS_REG_YEAR);
  t->century = rtc_read_reg(CMOS_REG_CENTURY);
}

static inline int rtc_equals(rtc_time_t* a, rtc_time_t* b) {
  return (
      a->seconds == b->seconds &&
      a->minutes == b->minutes &&
      a->hours == b->hours &&
      a->day_of_month == b->day_of_month &&
      a->month == b->month &&
      a->year == b->year &&
      a->century == b->century);
}

static inline uint8_t BCD_DECODE(uint8_t x) {
  return ((x >> 4) & 0x0F) * 10 + (x & 0x0F);
}

// TODO(aoates): unit tests for this!
static int rtc_decode(const rtc_time_t* raw_time, rtc_time_t* time) {
  if (raw_time->status_b & CMOS_STATUSB_BINARY_FMT) {
    *time = *raw_time;
  } else {
    time->seconds = BCD_DECODE(raw_time->seconds);
    time->minutes = BCD_DECODE(raw_time->minutes);
    time->hours = BCD_DECODE(raw_time->hours);
    time->day_of_month = BCD_DECODE(raw_time->day_of_month);
    time->month = BCD_DECODE(raw_time->month);
    time->year = BCD_DECODE(raw_time->year);
    time->century = BCD_DECODE(raw_time->century);
  }

  if (!(raw_time->status_b & CMOS_STATUSB_24HOUR)) {
    if (!(raw_time->status_b & CMOS_STATUSB_BINARY_FMT)) {
      // Extract and re-add the am/pm bit.
      time->hours =
          BCD_DECODE(raw_time->hours & ~0x80) | (raw_time->hours & 0x80);
    }
    if (raw_time->hours & 0x80) {
      time->hours = (raw_time->hours & ~0x80) + 12;
    }

    // Convert noon and midnight as needed.
    if (time->hours % 12 == 0) {
      time->hours -= 12;
    }
  }

  return 1;
}

int rtc_read_time(rtc_time_t* time) {
  // Read the state until it stabilizes.
  rtc_time_t times[2];
  rtc_read_state(&times[0]);
  rtc_read_state(&times[1]);
  int next_idx = 0, iters = 0;
  while (!rtc_equals(&times[0], &times[1])) {
    if (iters > 10) {
      klogf("ERROR: rtc value didn't stabilize after %d iterations\n", iters);
      return 0;
    }

    rtc_read_state(&times[next_idx]);
    next_idx = (next_idx + 1) % 2;
    iters++;
  }
  if (iters > 0) {
    klogf("rtc: time stabilized after %d iterations\n", iters);
  }
  return rtc_decode(&times[0], time);
}

void rtc_to_string(char* buf, rtc_time_t* t) {
  buf[0] = '\0';
  uint8_t disp_hours = t->hours % 12;
  if (disp_hours == 0) disp_hours = 12;
  ksprintf(buf, "%d/%d/%d %d:%d:%d %s",
           (uint32_t)t->month, (uint32_t)t->day_of_month,
           (uint32_t)(t->century * 100 + t->year),
           (uint32_t)disp_hours, (uint32_t)t->minutes,
           (uint32_t)t->seconds,
           t->hours < 12 ? "AM" : "PM");
}
