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

typedef unsigned long apos_rlim_t;

#define APOS_RLIM_INFINITY ULONG_MAX
#define APOS_RLIM_SAVED_MAX ULONG_MAX
#define APOS_RLIM_SAVED_CUR ULONG_MAX

#if __APOS_BUILDING_KERNEL__
#  define _APOS_RLIMIT apos_rlimit
#else
#  define _APOS_RLIMIT rlimit
#endif
struct _APOS_RLIMIT {
  apos_rlim_t rlim_cur;  // The current (soft) limit.
  apos_rlim_t rlim_max;  // The hard limit.
};
#undef _APOS_RLIMIT

// TODO(aoates): implement all of these.
// #define APOS_RLIMIT_CORE 0  // Limit on size of core file.
// #define APOS_RLIMIT_CPU 1  // Limit on CPU time per process.
// #define APOS_RLIMIT_DATA 2  // Limit on data segment size.
#define APOS_RLIMIT_FSIZE 3  // Limit on file size.
#define APOS_RLIMIT_NOFILE 4  // Limit on number of open files.
// #define APOS_RLIMIT_STACK 5  // Limit on stack size.
#define APOS_RLIMIT_AS 6  // Limit on address space size.
#define APOS_RLIMIT_NUM_RESOURCES 7

#if !__APOS_BUILDING_KERNEL__
  typedef apos_rlim_t rlim_t;
# define apos_rlimit rlimit

# define RLIM_INFINITY APOS_RLIM_INFINITY
# define RLIMIT_FSIZE APOS_RLIMIT_FSIZE
# define RLIMIT_NOFILE APOS_RLIMIT_NOFILE
# define RLIMIT_AS APOS_RLIMIT_AS
#endif

#endif
