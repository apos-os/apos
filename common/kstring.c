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

#include "common/kstring.h"

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
  uint32_t x = 0;
  while (*s1 && *s2 && x < n - 1) {
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
  for (uint32_t i = 0; i < n; ++i) {
    ((char*)s)[i] = c;
  }
  return s;
}

void* kmemcpy(void* dest, const void* src, uint32_t n) {
  for (uint32_t i = 0; i < n; i++) {
    ((uint8_t*)dest)[i] = ((uint8_t*)src)[i];
  }
  return dest;
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

static uint32_t abs(int32_t x) {
  return x < 0 ? -x : x;
}

const char* itoa(int32_t x) {
  static char buf[256];
  buf[0] = '\0';

  if (x < 0) {
    kstrcat(buf, "-");
  }
  kstrcat(buf, utoa(abs(x)));
  return buf;
}

const char* itoa_hex(int32_t x) {
  static char buf[256];
  buf[0] = '\0';

  if (x < 0) {
    kstrcat(buf, "-");
  }
  kstrcat(buf, utoa_hex(abs(x)));
  return buf;
}

// Helper for utoa/utoa_hex that takes a number, a base, and a lookup table of
// characters.
static const char* utoa_internal(uint32_t x, uint32_t base, const char* tbl) {
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

const char* utoa(uint32_t x) {
  return utoa_internal(x, 10, "0123456789");
}

const char* utoa_hex(uint32_t x) {
  return utoa_internal(x, 16, "0123456789ABCDEF");
}

static uint32_t atou_internal(const char* s) {
  uint32_t out = 0;
  while (*s) {
    if (*s < '0' || *s > '9') {
      break;
    }
    out = 10 * out + (*s - '0');
    s++;
  }
  return out;
}

int32_t atoi(const char* s) {
  if (*s == '-') {
    return -(int32_t)atou_internal(s+1);
  } else {
    return (int32_t)atou_internal(s);
  }
}

uint32_t atou(const char* s) {
  return atou_internal(s);
}

const char* kstrchr(const char* s, int c) {
  while (*s) {
    if (*s == c) {
      return s;
    }
    s++;
  }
  return 0;
}

const char* kstrrchr(const char* s, int c) {
  const int len = kstrlen(s);
  for (int i = len-1; i >= 0; --i) {
    if (s[i] == c) {
      return s + i;
    }
  }
  return 0;
}

const char* kstrchrnul(const char* s, int c) {
  while (*s) {
    if (*s == c) {
      return s;
    }
    s++;
  }
  return s;
}
