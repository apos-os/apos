// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_USER_INCLUDE_APOS_RESOURCE_H
#define APOO_USER_INCLUDE_APOS_RESOURCE_H

#include <limits.h>

typedef unsigned long rlim_t;

#define RLIM_INFINITY ULONG_MAX
#define RLIM_SAVED_MAX ULONG_MAX
#define RLIM_SAVED_CUR ULONG_MAX

struct rlimit {
  rlim_t rlim_cur;  // The current (soft) limit.
  rlim_t rlim_max;  // The hard limit.
};

// TODO(aoates): implement all of these.
// #define RLIMIT_CORE 0  // Limit on size of core file.
// #define RLIMIT_CPU 1  // Limit on CPU time per process.
// #define RLIMIT_DATA 2  // Limit on data segment size.
#define RLIMIT_FSIZE 3  // Limit on file size.
#define RLIMIT_NOFILE 4  // Limit on number of open files.
// #define RLIMIT_STACK 5  // Limit on stack size.
#define RLIMIT_AS 6  // Limit on address space size.
#define RLIMIT_NUM_RESOURCES 7

#endif
