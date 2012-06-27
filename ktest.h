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

#define KEXPECT_(name, astr, bstr, cond, condstr) do { \
  if (cond) { \
    klog("[PASSED] " name "(" astr ", " bstr ")\n"); \
  } else { \
    klog("[FAILED] " name "(" astr ", " bstr ") at " __FILE__ ":" STR(__LINE__) ": " condstr "\n"); \
  } \
} while(0)

#define KEXPECT_EQ(a, b) KEXPECT_("KEXPECT_EQ", #a, #b, a == b, #a " != " #b)
#define KEXPECT_NE(a, b) KEXPECT_("KEXPECT_NE", #a, #b, a != b, #a " == " #b)

#define KEXPECT_STREQ(a, b) KEXPECT_("KEXPECT_STREQ", #a, #b, !kstrcmp(a, b), #a " != " #b)
#define KEXPECT_STRNE(a, b) KEXPECT_("KEXPECT_STRNE", #a, #b, kstrcmp(a, b), #a " == " #b)

#define KEXPECT_LT(a, b) KEXPECT_("KEXPECT_LT", #a, #b, a < b, #a " >= " #b)
#define KEXPECT_LE(a, b) KEXPECT_("KEXPECT_LE", #a, #b, a <= b, #a " > " #b)

#define KEXPECT_GT(a, b) KEXPECT_("KEXPECT_GT", #a, #b, a > b, #a " <= " #b)
#define KEXPECT_GE(a, b) KEXPECT_("KEXPECT_GE", #a, #b, a >= b, #a " < " #b)

#endif
