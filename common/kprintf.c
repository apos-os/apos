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

#include <stdarg.h>
#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"

// A single printf component in the format string.
typedef struct {
  // Flags.
  bool zero_flag;
  bool space_flag;
  bool plus_flag;
  bool left_justify_flag;
  bool alternate_flag;

  int field_width;
  char length_mod;  // 'C' for 'hh', 'Q' for 'll'.
  char type;
} printf_spec_t;

static inline int is_digit(char c) {
  return c >= '0' && c <= '9';
}

static inline int is_flag(char c) {
  return c == ' ' || c == '0' || c == '+' || c == '-' || c == '#';
}

// Attempt to parse a printf_spec_t from the given string.  Returns the number
// of characters consumed, or -1 if it couldn't be extracted.
static int parse_printf_spec(const char* fmt, printf_spec_t* spec) {
  const char* const orig_fmt = fmt;
  KASSERT(*fmt == '%');
  fmt++;

  spec->zero_flag = false;
  spec->space_flag = false;
  spec->field_width = 0;
  spec->plus_flag = false;
  spec->left_justify_flag = false;
  spec->alternate_flag = false;
  spec->length_mod = ' ';

  // Parse flags.
  while (*fmt && is_flag(*fmt)) {
    if (*fmt == '0') spec->zero_flag = true;
    else if (*fmt == ' ') spec->space_flag = true;
    else if (*fmt == '+') spec->plus_flag = true;
    else if (*fmt == '-') spec->left_justify_flag = true;
    else if (*fmt == '#') spec->alternate_flag = true;
    fmt++;
  }

  // Field width.
  while (*fmt && is_digit(*fmt)) {
    spec->field_width *= 10;
    spec->field_width += *fmt - '0';
    fmt++;
  }

  if (!*fmt) return -1;

  if (*fmt == 'h' && *(fmt + 1) == 'h') {
    spec->length_mod = 'C';
    fmt += 2;
  } else if (*fmt == 'h' || *fmt == 'l' || *fmt == 'z') {
    spec->length_mod = *fmt;
    fmt++;
  }

  if (!*fmt) return -1;
  spec->type = *fmt++;
  return fmt - orig_fmt;
}

int ksprintf(char* str, const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int r = kvsprintf(str, fmt, args);
  va_end(args);
  return r;
}

int kvsprintf(char* str, const char* fmt, va_list args) {
  char* str_orig = str;
  _Static_assert(sizeof(long) <= 8, "buffer too small in printf");
  const char kNumBufSize = 22;
  char num_buf[kNumBufSize];

  while (*fmt) {
    if (*fmt != '%') {
      *(str++) = *(fmt++);
      continue;
    }

    printf_spec_t spec;
    const int spec_len = parse_printf_spec(fmt, &spec);
    if (spec_len < 0) {
      klog("invalid printf spec: ");
      klog(fmt);
      fmt++;
      continue;
    }

    const char* s;
    unsigned long uint;
    long sint;
    void* ptr;
    char chr[2];

    bool numeric = true;
    bool positive_number = false;
    const char* prefix = "";

    switch (spec.type) {
      case '%':
        s = "%";
        numeric = false;
        break;

      case 's':
        s = va_arg(args, const char*);
        numeric = false;
        break;

      case 'c':
        chr[0] = (char)va_arg(args, int);
        chr[1] = '\0';
        s = chr;
        numeric = false;
        break;

      case 'd':
      case 'i':
        switch (spec.length_mod) {
          case ' ':
          case 'C':
          case 'h':
            sint = va_arg(args, int);
            break;
          case 'l':
            sint = va_arg(args, long);
            break;
          case 'z':
            sint = va_arg(args, ssize_t);
            break;
          default:
            klogm(KL_GENERAL, DFATAL,
                  "invalid length modifier (shouldn't have been parsed)\n");
            sint = 0;
            break;
        }

        positive_number = sint >= 0;
        s = kitoa_r(sint, num_buf, kNumBufSize);
        break;

      case 'u':
      case 'x':
      case 'X':
        switch (spec.length_mod) {
          case ' ':
          case 'C':
          case 'h':
            uint = va_arg(args, unsigned int);
            break;
          case 'l':
            uint = va_arg(args, unsigned long);
            break;
          case 'z':
            uint = va_arg(args, size_t);
            break;
          default:
            klogm(KL_GENERAL, DFATAL,
                  "invalid length modifier (shouldn't have been parsed)\n");
            uint = 0;
            break;
        }

        switch (spec.type) {
          case 'u':
            s = kutoa_r(uint, num_buf, kNumBufSize);
            break;

          case 'x':
            s = kutoa_hex_lower_r(uint, num_buf, kNumBufSize);
            if (uint != 0 && spec.alternate_flag) prefix = "0x";
            break;

          case 'X':
            s = kutoa_hex_r(uint, num_buf, kNumBufSize);
            if (uint != 0 && spec.alternate_flag) prefix = "0X";
            break;
        }
        break;

      case 'p':
        ptr = va_arg(args, void*);
        s = kutoa_hex_lower_r((intptr_t)ptr, num_buf, kNumBufSize);
        prefix = "0x";
        break;

      default:
        klog("ERROR: unknown printf character.\n");
        s = "";
    }
    int len = kstrlen(s);

    // The printed value is composed of several parts, in order.  Each may be
    // empty:
    //  * left space padding: spaces to pad to field width
    //  * symbol: symbol for positive numbers (e.g. '+' or ' ')
    //  * prefix: value prefix (eg. '0x' or '0X')
    //  * zero padding: zeroes to pad to field width
    //  * value: the actual value being printed
    //  * right space padding: spaces to pad to field width, if left-justified

    // Figure out if we need a symbol, and adjust s and len as necessary.
    char symbol = '\0';
    if (numeric && spec.space_flag && !spec.plus_flag && positive_number) {
      symbol = ' ';
      len++;
    } else if (numeric && spec.plus_flag && positive_number) {
      symbol = '+';
      len++;
    } else if (numeric && s[0] == '-') {
      symbol = '-';
      s++;
    }

    len += kstrlen(prefix);

    // Left space padding.
    if (!spec.left_justify_flag && (!spec.zero_flag || !numeric)) {
      for (int i = 0; i + len < spec.field_width; ++i) *str++ = ' ';
    }

    // Add the symbol.
    if (symbol) *str++ = symbol;

    // Add the prefix.
    while (*prefix) *str++ = *prefix++;

    // Zero padding.
    if (!spec.left_justify_flag && spec.zero_flag && numeric) {
      for (int i = 0; i + len < spec.field_width; ++i) *str++ = '0';
    }

    // Copy over the remaining value.
    while (*s) *str++ = *s++;

    // Second space padding.
    if (spec.left_justify_flag) {
      for (int i = 0; i + len < spec.field_width; ++i) *str++ = ' ';
    }

    fmt += spec_len;
  }
  *str = '\0';

  return str - str_orig;
}
