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

#include <stddef.h>

#include "common/arch-config.h"
#include "common/time.h"
#include "dev/rtc/goldfish-rtc.h"
#include "dev/rtc/pc_rtc.h"
#include "user/include/apos/errors.h"

int apos_get_time(struct apos_tm* t) {
  if (t == NULL) return -EINVAL;

#if ARCH_SUPPORTS_LEGACY_PC_DEVS
  pcrtc_time_t rtc;
  int result = pcrtc_read_time(&rtc);
  if (result != 0) {
    return result;
  }

  t->tm_sec = rtc.seconds;
  t->tm_min = rtc.minutes;
  t->tm_hour = rtc.hours;
  t->tm_mday = rtc.day_of_month;
  t->tm_mon = rtc.month - 1;
  t->tm_year = rtc.year + rtc.century * 100 - 1900;

  return 0;
#else
  return -ENOTSUP;
#endif
}

int apos_get_timespec(struct apos_timespec* ts) {
  return goldfish_rtc_read(ts);
}

long timespec2ms(const struct apos_timespec* ts) {
  return ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
}
