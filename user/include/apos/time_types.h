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

#ifndef APOO_USER_INCLUDE_APOS_TIME_TYPES_H
#define APOO_USER_INCLUDE_APOS_TIME_TYPES_H

#if __APOS_BUILDING_IN_TREE__
#  include "user/include/apos/posix_types.h"
#else
#  include <apos/posix_types.h>
#endif

struct timespec {
  time_t  tv_sec;
  long    tv_nsec;
};

// Similar to POSIX struct tm.
struct apos_tm {
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
};

#endif
