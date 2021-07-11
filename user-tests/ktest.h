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

void kexpect(int cond, const char* name, const char* astr,
             const char* bstr, const char* aval, const char* bval,
             const char* val_surrounders, const char* opstr, const char* file,
             const char* line);

typedef enum {
  PRINT_SIGNED,
  PRINT_UNSIGNED,
  PRINT_HEX,
  PRINT_UNKNOWN,
} kexpect_print_t;

void kexpect_int(const char* name, const char* file, const char* line,
                 const char* astr, const char* bstr, long aval, long bval,
                 long result, const char* opstr, kexpect_print_t a_type,
                 kexpect_print_t b_type);

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

#define KEXPECT_(name, astr, bstr, a, b, cond_func, opstr)                    \
  do {                                                                        \
    const char* aval = a;                                                     \
    const char* bval = b;                                                     \
    kexpect(cond_func(aval, bval), name, astr, bstr, aval, bval, "'", opstr, \
             __FILE__, STR(__LINE__));                                        \
  } while (0)

#define KEXPECT_INT_(name, astr, bstr, a, b, op, opstr)                \
  do {                                                                 \
    typeof(a) aval = a;                                                \
    typeof(a) bval = b;                                                \
    kexpect_int(name, __FILE__, STR(__LINE__), astr, bstr, (long)aval, \
                (long)bval, (aval op bval), opstr, PRINT_TYPE(a),      \
                PRINT_TYPE(b));                                        \
  } while (0)

#define KEXPECT_EQ(a, b) KEXPECT_INT_("KEXPECT_EQ", #a, #b, a, b, ==, " != ")
#define KEXPECT_NE(a, b) KEXPECT_INT_("KEXPECT_NE", #a, #b, a, b, !=, " == ")

#define KEXPECT_STREQ(a, b) KEXPECT_("KEXPECT_STREQ", #a, #b, a, b, !strcmp, " != ")
#define KEXPECT_STRNE(a, b) KEXPECT_("KEXPECT_STRNE", #a, #b, a, b, strcmp, " == ")

#define KEXPECT_LT(a, b) KEXPECT_INT_("KEXPECT_LT", #a, #b, a, b, <, " >= ")
#define KEXPECT_LE(a, b) KEXPECT_INT_("KEXPECT_LE", #a, #b, a, b, <=, " > ")

#define KEXPECT_GT(a, b) KEXPECT_INT_("KEXPECT_GT", #a, #b, a, b, >, " <= ")
#define KEXPECT_GE(a, b) KEXPECT_INT_("KEXPECT_GE", #a, #b, a, b, >=, " < ")

#define KEXPECT_TRUE(b) \
  KEXPECT_INT_("KEXPECT_TRUE", "true", #b, true, ((bool)(b)), ==, " == ")

// Initialize the testing framework.
void ktest_begin_all(void);

// Tear down the framework and print statistics about passing/failing tests.
// Returns 0 if all tests passed, 1 otherwise.
int ktest_finish_all(void);

#endif
