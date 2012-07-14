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

// Kernel unit-testing framework.
#ifndef APOO_KTEST_H
#define APOO_KTEST_H

#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"

#define STR2(x) #x
#define STR(x) STR2(x)

void KTEST_SUITE_BEGIN(const char* name);
void KTEST_BEGIN(const char* name);

void kexpect_(uint32_t cond, const char* name,
              const char* astr, const char* bstr,
              const char* aval, const char* bval,
              const char* opstr,
              const char* file, const char* line);

#define KEXPECT_(name, astr, bstr, a, b, cond_func, opstr) do { \
  const char* aval = a; \
  const char* bval = b; \
  uint32_t cond = cond_func(aval, bval); \
  kexpect_(cond, name, astr, bstr, aval, bval, opstr, __FILE__, STR(__LINE__)); \
} while(0)

#define KEXPECT_INT_(name, astr, bstr, a, b, op, opstr) do { \
  typeof(a) aval = a; \
  typeof(a) bval = b; \
  char aval_str[50]; \
  char bval_str[50]; \
  /* If the expected value is written as hex, print the actual value as hex too.*/ \
  if (kstrncmp(astr, "0x", 2) == 0 || kstrncmp(bstr, "0x", 2) == 0) { \
    ksprintf(aval_str, "0x%s", utoa_hex(aval)); \
    ksprintf(bval_str, "0x%s", utoa_hex(bval)); \
  } else if (kstrncmp(astr, "-", 1) == 0 || kstrncmp(bstr, "-", 1) == 0) { \
    kstrcpy(aval_str, itoa(aval)); \
    kstrcpy(bval_str, itoa(bval)); \
  } else { \
    kstrcpy(aval_str, utoa(aval)); \
    kstrcpy(bval_str, utoa(bval)); \
  } \
  kexpect_((aval op bval), name, astr, bstr, aval_str, bval_str, opstr, __FILE__, STR(__LINE__)); \
} while(0)

#define KEXPECT_EQ(a, b) KEXPECT_INT_("KEXPECT_EQ", #a, #b, a, b, ==, " != ")
#define KEXPECT_NE(a, b) KEXPECT_INT_("KEXPECT_NE", #a, #b, a, b, !=, " == ")

#define KEXPECT_STREQ(a, b) KEXPECT_("KEXPECT_STREQ", #a, #b, a, b, !kstrcmp, " != ")
#define KEXPECT_STRNE(a, b) KEXPECT_("KEXPECT_STRNE", #a, #b, a, b, kstrcmp, " == ")

#define KEXPECT_LT(a, b) KEXPECT_INT_("KEXPECT_LT", #a, #b, a, b, <, " >= ")
#define KEXPECT_LE(a, b) KEXPECT_INT_("KEXPECT_LE", #a, #b, a, b, <=, " > ")

#define KEXPECT_GT(a, b) KEXPECT_INT_("KEXPECT_GT", #a, #b, a, b, >, " <= ")
#define KEXPECT_GE(a, b) KEXPECT_INT_("KEXPECT_GE", #a, #b, a, b, >=, " < ")

// Initialize the testing framework.
void ktest_begin_all();

// Tear down the framework and print statistics about passing/failing tests.
void ktest_finish_all();

#endif
