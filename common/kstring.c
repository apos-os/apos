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

#include "common/attributes.h"
#include "common/config.h"
#include "common/kstring.h"
#include "common/math.h"

#if ENABLE_TSAN
#include "sanitizers/tsan/tsan_hooks.h"
#endif

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
  if (n == 0) return 0;
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

bool kstr_startswith(const char* s, const char* prefix) {
  while (*s && *prefix) {
    if (*s != *prefix) {
      return false;
    }
    s++;
    prefix++;
  }
  return (*prefix == '\0');
}

// If TSAN is enabled, generate _no_tsan versions of the builtins, and
// TSAN-aware wrappers that register the access then call the builtin.
#if ENABLE_TSAN
# define DEF_TSAN(name) NO_TSAN name##_no_tsan

void* kmemset(void* s, int c, size_t n) {
  return __tsan_memset(s, c, n);
}

void* kmemcpy(void* dest, const void* src, size_t n) {
  return __tsan_memcpy(dest, src, n);
}

#else
# define DEF_TSAN(name) name
#endif

void* DEF_TSAN(kmemset)(void* s, int c, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    ((char*)s)[i] = c;
  }
  return s;
}

void* DEF_TSAN(kmemcpy)(void* dest, const void* src, size_t n) {
  for (size_t i = 0; i < n; i++) {
    ((uint8_t*)dest)[i] = ((uint8_t*)src)[i];
  }
  return dest;
}

// Emit memset as an alias to kmemset.  The compiler will emit calls to memset,
// which will now call kmemset.  Likewise with memcpy.
//
// If TSAN is enabled, redirect implicitly generated calls to memset/etc to the
// no-TSAN versions --- in TSAN-instrumented code, calls to __tsan_memset() will
// be generated instead.  In NO_TSAN code, we want implicit memset() (etc) calls
// to direct to kmemset_no_tsan(), NOT kmemset() (which calls __tsan_memset()).
#if ENABLE_TSAN
void* memset(void* dest, int c, size_t n)
    __attribute__((alias("kmemset_no_tsan")));
void* memcpy(void* dest, const void* src, size_t n)
    __attribute__((alias("kmemcpy_no_tsan")));
#else
void* memset(void* dest, int c, size_t n) __attribute__((alias("kmemset")));
void* memcpy(void* dest, const void* src, size_t n)
    __attribute__((alias("kmemcpy")));
#endif

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
  kstrlcat(dst, src, SIZE_MAX);  // Insecure!
  return dst;
}

size_t kstrlcat(char* dst, const char* src, size_t dst_size) {
  size_t copied = 0;
  // Find the end of the existing dst string (up to dst_size).
  while (dst[copied] != '\0' && copied + 1 < dst_size) {
    copied++;
  }
  // To handle the case of 'dst' being an invalid string (not terminated).
  if (copied + 1 < dst_size) {
    // Copy until we run out of source or buffer (leaving room for NULL).
    while (*src && copied + 1 < dst_size) {
      dst[copied++] = *(src++);
    }
    dst[copied] = '\0';
  }
  // Find the end of src for the return value.
  while (*src) {
    src++;
    copied++;
  }
  // Return length of string we would have copied given room.
  return copied;
}

const char* kitoa(long x) {
  static char buf[256];
  return kitoa_r(x, buf, 256);
}

const char* kitoa_r(long x, char* buf, size_t len) {
  buf[0] = '\0';

  char* orig_buf = buf;
  if (x < 0 && len > 1) {
    kstrcat(buf, "-");
    len--;
    buf++;
  }
  kutoa_r(abs(x), buf, len);
  return orig_buf;
}

const char* kitoa_hex(long x) {
  static char buf[256];
  return kitoa_hex_r(x, buf, 256);
}

const char* kitoa_hex_r(long x, char* buf, size_t len) {
  buf[0] = '\0';

  char* orig_buf = buf;
  if (x < 0 && len > 1) {
    kstrcat(buf, "-");
    len--;
    buf++;
  }
  kutoa_hex_r(abs(x), buf, len);
  return orig_buf;
}

// Helper for utoa/utoa_hex that takes a number, a base, and a lookup table of
// characters.
static const char* kutoa_internal(unsigned long x, unsigned long base,
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

const char* kutoa(unsigned long x) {
  static char buf[256];
  return kutoa_r(x, buf, 256);
}

const char* kutoa_r(unsigned long x, char* buf, size_t len) {
  return kutoa_internal(x, 10, "0123456789", buf, len);
}

const char* kutoa_hex(unsigned long x) {
  static char buf[256];
  return kutoa_hex_r(x, buf, 256);
}

const char* kutoa_hex_r(unsigned long x, char* buf, size_t len) {
  return kutoa_internal(x, 16, "0123456789ABCDEF", buf, len);
}

const char* kutoa_hex_lower(unsigned long x) {
  static char buf[256];
  return kutoa_hex_lower_r(x, buf, 256);
}

const char* kutoa_hex_lower_r(unsigned long x, char* buf, size_t len) {
  return kutoa_internal(x, 16, "0123456789abcdef", buf, len);
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

unsigned long katou_hex(const char* s) {
  if (kstrncmp(s, "0x", 2) == 0 ||
      kstrncmp(s, "0X", 2) == 0) {
    s += 2;
  }
  return atou_internal_base(s, 16);
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
