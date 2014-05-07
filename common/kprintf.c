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
  int field_width;
  char type;
} printf_spec_t;

static inline int is_digit(char c) {
  return c >= '0' && c <= '9';
}

// Attempt to parse a printf_spec_t from the given string.  Returns the number
// of characters consumed, or -1 if it couldn't be extracted.
static int parse_printf_spec(const char* fmt, printf_spec_t* spec) {
  const char* const orig_fmt = fmt;
  KASSERT(*fmt == '%');
  fmt++;

  // Field width.
  spec->field_width = 0;
  while (*fmt && is_digit(*fmt)) {
    spec->field_width *= 10;
    spec->field_width += *fmt - '0';
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
    uint32_t uint;
    int32_t sint;

    switch (spec.type) {
      case '%':
        s = "%";
        break;

      case 's':
        s = va_arg(args, const char*);
        break;

      case 'd':
      case 'i':
        sint = va_arg(args, int32_t);
        s = itoa(sint);
        break;

      case 'u':
        uint = va_arg(args, uint32_t);
        s = utoa(uint);
        break;

      case 'x':
      case 'X':
        uint = va_arg(args, uint32_t);
        s = utoa_hex(uint);
        break;

      default:
        klog("ERROR: unknown printf character.\n");
        s = "";
    }
    int len = kstrlen(s);
    for (int i = 0; i + len < spec.field_width; ++i) *str++ = ' ';
    kstrncpy(str, s, len);
    str += len;
    fmt += spec_len;
  }
  *str = '\0';

  return str - str_orig;
}
