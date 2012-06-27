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

// Utilities for kernel unit tests.
#ifndef APOO_KTEST_H
#define APOO_KTEST_H

#include "klog.h"

#define STR2(x) #x
#define STR(x) STR2(x)

#define KTEST_SUITE_BEGIN(name) do { \
  klog("\n\nTEST SUITE: " name "\n"); \
  klog("#######################################\n"); \
} while (0)

#define KTEST_BEGIN(name) do { \
  klog("\nTEST: " name "\n"); \
  klog("---------------------------------------\n"); \
} while(0)

#define KEXPECT_EQ(a, b) do { \
  if (a != b) { \
    klog("[FAILED] KEXPECT_EQ(" #a ", " #b ") at " __FILE__ ":" STR(__LINE__) ": " #a " != " #b "\n"); \
  } else { \
    klog("[PASSED] KEXPECT_EQ(" #a ", " #b ")\n"); \
  } \
} while(0)

#define KEXPECT_STREQ(a, b) do { \
  if (kstrcmp(a, b)) { \
    klog("[FAILED] KEXPECT_STREQ(" #a ", " #b ") at " __FILE__ ":" STR(__LINE__) ": " #a " != " #b "\n"); \
  } else { \
    klog("[PASSED] KEXPECT_STREQ(" #a ", " #b ")\n"); \
  } \
} while(0)

#define KEXPECT_NE(a, b) do { \
  if (a == b) { \
    klog("[FAILED] KEXPECT_NE(" #a ", " #b ") at " __FILE__ ":" STR(__LINE__) ": " #a " == " #b "\n"); \
  } else { \
    klog("[PASSED] KEXPECT_NE(" #a ", " #b ")\n"); \
  } \
} while(0)

#define KEXPECT_STRNE(a, b) do { \
  if (kstrcmp(a, b)) { \
    klog("[FAILED] KEXPECT_STRNE(" #a ", " #b ") at " __FILE__ ":" STR(__LINE__) ": " #a " != " #b "\n"); \
  } else { \
    klog("[PASSED] KEXPECT_STRNE(" #a ", " #b ")\n"); \
  } \
} while(0)

#endif
