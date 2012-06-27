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

#include "kstring.h"

#include <stdint.h>

int kstrlen(const char* s) {
  int x = 0;
  while (*s) {
    ++s;
    ++x;
  }
  return x;
}

int kstrcmp(const char* s1, const char* s2) {
  while (*s1 && *s2) {
    if (*s1 != *s2) {
      return *s1 - *s2;
    }
    ++s1;
    ++s2;
  }
  return *s1 - *s2;
}

int kstrncmp(const char* s1, const char* s2, uint32_t n) {
  int x = 0;
  while (*s1 && *s2 && x < n) {
    if (*s1 != *s2) {
      return *s1 - *s2;
    }
    ++s1;
    ++s2;
    ++x;
  }
  return *s1 - *s2;
}

void* kmemset(void *s, int c, uint32_t n) {
  for (int i = 0; i < n; ++i) {
    ((char*)s)[i] = c;
  }
  return s;
}

char* kstrcpy(char* dst, const char* src) {
  char* dst_out = dst;
  while (*src) {
    *(dst_out++) = *(src++);
  }
  *dst_out = '\0';
  return dst;
}

char* kstrncpy(char* dst, const char* src, uint32_t n) {
  char* dst_out = dst;
  uint32_t i = 0;
  while (*src && i < n) {
    *(dst_out++) = *(src++);
    i++;
  }
  *dst_out = '\0';
  return dst;
}

char* kstrcat(char* dst, const char* src) {
  char* dst_orig = dst;
  const int len = kstrlen(dst);
  dst += len;
  while (*src) {
    *(dst++) = *(src++);
  }
  *dst = '\0';
  return dst_orig;
}

// Helper for itoa/itoa_hex that takes a number, a base, and a lookup table of
// characters.
static const char* itoa_internal(uint32_t x, uint32_t base, const char* tbl) {
  static char buf[256];
  int i = 0;
  if (x == 0) {
    buf[i] = tbl[0];
    buf[i+1] = '\0';
  } else {
    while (x > 0) {
      buf[i++] = tbl[x % base];
      x /= base;
    }
    buf[i] = '\0';
    int len = i;
    for (i = 0; i < len/2; ++i) {
      char tmp = buf[i];
      buf[i] = buf[len-i-1];
      buf[len-i-1] = tmp;
    }
  }
  return buf;
}

const char* itoa(uint32_t x) {
  return itoa_internal(x, 10, "0123456789");
}

const char* itoa_hex(uint32_t x) {
  return itoa_internal(x, 16, "0123456789ABCDEF");
}
