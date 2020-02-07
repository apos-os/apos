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

int kstrnlen(const char* s, int max) {
  int x = 0;
  while (*s && max > 0) {
    ++s;
    ++x;
    --max;
  }
  if (max == 0) return -1;
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

int kstrncmp(const char* s1, const char* s2, size_t n) {
  size_t x = 0;
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

void* kmemset(void *s, int c, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    ((char*)s)[i] = c;
  }
  return s;
}

void* kmemcpy(void* dest, const void* src, size_t n) {
  for (size_t i = 0; i < n; i++) {
    ((uint8_t*)dest)[i] = ((uint8_t*)src)[i];
  }
  return dest;
}

int kmemcmp(const void* m1, const void* m2, size_t n) {
  const char* s1 = (const char*)m1;
  const char* s2 = (const char*)m2;
  while (n > 0) {
    if (*s1 != *s2) {
      return *s1 - *s2;
    }
    ++s1;
    ++s2;
    --n;
  }
  return 0;
}

char* kstrcpy(char* dst, const char* src) {
  char* dst_out = dst;
  while (*src) {
    *(dst_out++) = *(src++);
  }
  *dst_out = '\0';
  return dst;
}

char* kstrncpy(char* dst, const char* src, size_t n) {
  char* dst_out = dst;
  size_t i = 0;
  while (*src && i < n) {
    *(dst_out++) = *(src++);
    i++;
  }
  if (i < n) *(dst_out++) = '\0';
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

static unsigned long abs(long x) {
  return x < 0 ? -x : x;
}

const char* itoa(long x) {
  static char buf[256];
  return itoa_r(x, buf, 256);
}

const char* itoa_r(long x, char* buf, size_t len) {
  buf[0] = '\0';

  char* orig_buf = buf;
  if (x < 0 && len > 1) {
    kstrcat(buf, "-");
    len--;
    buf++;
  }
  utoa_r(abs(x), buf, len);
  return orig_buf;
}

const char* itoa_hex(long x) {
  static char buf[256];
  return itoa_hex_r(x, buf, 256);
}

const char* itoa_hex_r(long x, char* buf, size_t len) {
  buf[0] = '\0';

  char* orig_buf = buf;
  if (x < 0 && len > 1) {
    kstrcat(buf, "-");
    len--;
    buf++;
  }
  utoa_hex_r(abs(x), buf, len);
  return orig_buf;
}

// Helper for utoa/utoa_hex that takes a number, a base, and a lookup table of
// characters.
static const char* utoa_internal(unsigned long x, unsigned long base,
                                 const char* tbl, char* buf, size_t buflen) {
  int i = 0;
  if (buflen == 1) {
    buf[0] = '\0';
    return buf;
  }
  if (x == 0) {
    buf[i] = tbl[0];
    buf[i+1] = '\0';
  } else {
    while (x > 0 && buflen > 1) {
      buf[i++] = tbl[x % base];
      x /= base;
      buflen--;
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

const char* utoa(unsigned long x) {
  static char buf[256];
  return utoa_r(x, buf, 256);
}

const char* utoa_r(unsigned long x, char* buf, size_t len) {
  return utoa_internal(x, 10, "0123456789", buf, len);
}

const char* utoa_hex(unsigned long x) {
  static char buf[256];
  return utoa_hex_r(x, buf, 256);
}

const char* utoa_hex_r(unsigned long x, char* buf, size_t len) {
  return utoa_internal(x, 16, "0123456789ABCDEF", buf, len);
}

const char* utoa_hex_lower(unsigned long x) {
  static char buf[256];
  return utoa_hex_lower_r(x, buf, 256);
}

const char* utoa_hex_lower_r(unsigned long x, char* buf, size_t len) {
  return utoa_internal(x, 16, "0123456789abcdef", buf, len);
}

static unsigned long atou_internal_base(const char* s, int base) {
  if (base != 10 && base != 16) {
    return 0;
  }
  unsigned long out = 0;
  while (*s) {
    int digit = 0;
    if (*s >= '0' && *s <= '9') {
      digit = *s - '0';
    } else if (base == 16 && *s >= 'a' && *s <= 'f') {
      digit = *s - 'a' + 10;
    } else if (base == 16 && *s >= 'A' && *s <= 'F') {
      digit = *s - 'A' + 10;
    } else {
      // Invalid digit.
      break;
    }
    out = base * out + digit;
    s++;
  }
  return out;
}

static unsigned long atou_internal(const char* s) {
  if (kstrncmp(s, "0x", 2) == 0 ||
      kstrncmp(s, "0X", 2) == 0) {
    return atou_internal_base(s + 2, 16);
  } else {
    return atou_internal_base(s, 10);
  }
}

long katoi(const char* s) {
  if (*s == '-') {
    return -(long)atou_internal(s+1);
  } else {
    return (long)atou_internal(s);
  }
}

unsigned long katou(const char* s) {
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
