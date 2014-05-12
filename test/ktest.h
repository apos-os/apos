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

#include "common/errno.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"

#define KLOG(...) klogfm(KL_TEST, INFO, __VA_ARGS__)

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
void kexpect_int_to_string(int aval, int bval, char* aval_str, char* bval_str);

typedef enum {
  PRINT_SIGNED,
  PRINT_UNSIGNED,
  PRINT_HEX,
  PRINT_UNKNOWN,
} kexpect_print_t;

// GCC doesn't support C11 generic macros yet :/
#ifdef SUPPORTS_GENERIC_MACROS

#define PRINT_TYPE(expr) \
    _Generic((expr), \
             int8_t: PRINT_SIGNED, \
             int16_t: PRINT_SIGNED, \
             int32_t: PRINT_SIGNED, \
             int64_t: PRINT_SIGNED, \
             uint8_t: PRINT_UNSIGNED, \
             uint16_t: PRINT_UNSIGNED, \
             uint32_t: PRINT_UNSIGNED, \
             uint64_t: PRINT_UNSIGNED, \
             void*: PRINT_HEX, \
             default: PRINT_HEX)

#else

#ifdef __GNUC__

#define PRINT_TYPE(expr) \
    ({ \
     kexpect_print_t _type; \
     if (__builtin_types_compatible_p(typeof(expr), char) || \
         __builtin_types_compatible_p(typeof(expr), short) || \
         __builtin_types_compatible_p(typeof(expr), int) || \
         __builtin_types_compatible_p(typeof(expr), long) || \
         __builtin_types_compatible_p(typeof(expr), long long) || \
         __builtin_types_compatible_p(typeof(expr), int8_t) || \
         __builtin_types_compatible_p(typeof(expr), int16_t) || \
         __builtin_types_compatible_p(typeof(expr), int32_t) || \
         __builtin_types_compatible_p(typeof(expr), int64_t)) { \
       _type = PRINT_SIGNED; \
     } else if (__builtin_types_compatible_p(typeof(expr), unsigned char) || \
                __builtin_types_compatible_p(typeof(expr), unsigned short) || \
                __builtin_types_compatible_p(typeof(expr), unsigned int) || \
                __builtin_types_compatible_p(typeof(expr), unsigned long) || \
                __builtin_types_compatible_p(typeof(expr), unsigned long long) || \
                __builtin_types_compatible_p(typeof(expr), uint8_t) || \
                __builtin_types_compatible_p(typeof(expr), uint16_t) || \
                __builtin_types_compatible_p(typeof(expr), uint32_t) || \
                __builtin_types_compatible_p(typeof(expr), uint64_t)) { \
       _type = PRINT_UNSIGNED; \
     } else { \
       _type = PRINT_HEX; \
     } \
     _type; \
   })

#else // __GNUC__

#define PRINT_TYPE(expr) PRINT_UNKNOWN

#endif // __GNUC__

#endif // SUPPORTS_GENERIC_MACROS

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
      kstrncmp(astr, "0x", 2) == 0 || kstrncmp(bstr, "0x", 2) == 0) { \
    ksprintf(aval_str, "0x%s", utoa_hex((uint32_t)aval)); \
    ksprintf(bval_str, "0x%s", utoa_hex((uint32_t)bval)); \
  } else if (PRINT_TYPE(a) == PRINT_SIGNED || \
             kstrncmp(astr, "-", 1) == 0 || kstrncmp(bstr, "-", 1) == 0) { \
    kexpect_int_to_string((int)aval, (int)bval, aval_str, bval_str); \
  } else { \
    kstrcpy(aval_str, utoa((uint32_t)aval)); \
    kstrcpy(bval_str, utoa((uint32_t)bval)); \
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

#endif
