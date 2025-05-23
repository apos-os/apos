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

#ifndef APOO_COMMON_TIME_H
#define APOO_COMMON_TIME_H

#include "user/include/apos/posix_types.h"
#include "user/include/apos/time_types.h"

#define NANOS_PER_SECOND 1000000000

// Return the current time can best be determined.  Note that platforms may
// support zero, one, or all of the following.
int apos_get_time(struct apos_tm* t);
int apos_get_timespec(struct apos_timespec* ts);

// Convert an apos_timespec into a milliseconds count.
long timespec2ms(const struct apos_timespec* ts);

#endif
