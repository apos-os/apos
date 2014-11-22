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

// Kernel unit-testing framework.  Adapted for user-space tests.
#ifndef APOO_USER_KTEST_H
#define APOO_USER_KTEST_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define STR2(x) #x
#define STR(x) STR2(x)

void KTEST_SUITE_BEGIN(const char* name);
void KTEST_BEGIN(const char* name);

void kexpect_(uint32_t cond, const char* name,
              const char* astr, const char* bstr,
              const char* aval, const char* bval,
              const char* val_surrounders, const char* opstr,
              const char* file, const char* line);

// Convert two integer values into strings, appending the errorname if it looks
// like an error code is being returned (one of the operands is zero, and the
// other is between -ERRNO_MIN and -ERRNO_MAX).
static inline void kexpect_int_to_string(int aval, int bval, char* aval_str,
                                         char* bval_str);

typedef enum {
  PRINT_SIGNED,
  PRINT_UNSIGNED,
  PRINT_HEX,
  PRINT_UNKNOWN,
} kexpect_print_t;

#define PRINT_TYPE(expr) \
    _Generic((expr), \
             char: PRINT_SIGNED, \
             short: PRINT_SIGNED, \
             int: PRINT_SIGNED, \
             long: PRINT_SIGNED, \
             long long: PRINT_SIGNED, \
             unsigned char: PRINT_UNSIGNED, \
             unsigned short: PRINT_UNSIGNED, \
             unsigned int: PRINT_UNSIGNED, \
             unsigned long: PRINT_UNSIGNED, \
             unsigned long long: PRINT_UNSIGNED, \
             void*: PRINT_HEX, \
             default: PRINT_HEX)

#define KEXPECT_(name, astr, bstr, a, b, cond_func, opstr) do { \
  const char* aval = a; \
  const char* bval = b; \
  uint32_t cond = cond_func(aval, bval); \
  kexpect_(cond, name, astr, bstr, aval, bval, "'", opstr, __FILE__, STR(__LINE__)); \
} while(0)

#define KEXPECT_INT_(name, astr, bstr, a, b, op, opstr) do { \
  typeof(a) aval = a; \
  typeof(a) bval = b; \
  char aval_str[50]; \
  char bval_str[50]; \
  /* If the expected value is written as hex, print the actual value as hex too.*/ \
  if (PRINT_TYPE(a) == PRINT_HEX || \
      strncmp(astr, "0x", 2) == 0 || strncmp(bstr, "0x", 2) == 0) { \
    sprintf(aval_str, "%#x", (int)aval); \
    sprintf(bval_str, "%#x", (int)bval); \
  } else if (PRINT_TYPE(a) == PRINT_SIGNED || \
             strncmp(astr, "-", 1) == 0 || strncmp(bstr, "-", 1) == 0) { \
    kexpect_int_to_string((int)aval, (int)bval, aval_str, bval_str); \
  } else { \
    sprintf(aval_str, "%d", (int)aval); \
    sprintf(bval_str, "%d", (int)bval); \
  } \
  kexpect_((aval op bval), name, astr, bstr, aval_str, bval_str, "", opstr, __FILE__, STR(__LINE__)); \
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
void ktest_begin_all(void);

// Tear down the framework and print statistics about passing/failing tests.
void ktest_finish_all(void);

/***  Implementation details ***/

static inline void kexpect_int_to_string(int aval, int bval, char* aval_str,
                                         char* bval_str) {
  const int aval_in_range = 0; //aval >= -ERRNO_MAX && aval <= -ERRNO_MIN;
  const int bval_in_range = 0; //bval >= -ERRNO_MAX && bval <= -ERRNO_MIN;

  sprintf(aval_str, "%d", aval);
  if ((bval_in_range || bval == 0) && aval_in_range) {
    strcat(aval_str, " (");
    strcat(aval_str, strerror(-aval));
    strcat(aval_str, ")");
  }
  sprintf(bval_str, "%d", bval);
  if ((aval_in_range || aval == 0) && bval_in_range) {
    strcat(bval_str, " (");
    strcat(bval_str, strerror(-bval));
    strcat(bval_str, ")");
  }
}

#endif
