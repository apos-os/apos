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

#ifndef APOO_KSTRING_H
#define APOO_KSTRING_H

#include <stddef.h>
#include <stdint.h>

// Clang will generate calls to memset(), so we must define it.
#if defined(__clang__) && __clang__
#  define kmemset memset
#endif

int kstrlen(const char* s);
int kstrcmp(const char* s1, const char* s2);
int kstrncmp(const char* s1, const char* s2, size_t n);

void* kmemset(void* s, int c, size_t n);
void* kmemcpy(void* dest, const void* src, size_t n);
int kmemcmp(const void* s1, const void* s2, size_t n);

char* kstrcpy(char* dst, const char* src);
char* kstrncpy(char* dst, const char* src, size_t n);

char *kstrcat(char *dest, const char *src);

const char* itoa(int32_t x);
const char* itoa_hex(int32_t x);

const char* utoa(uint32_t x);
const char* utoa_hex(uint32_t x);
const char* utoa_hex_lower(uint32_t x);  // As above, but lower case.

// Note: these only support decimal.
int32_t atoi(const char* s);
uint32_t atou(const char* s);

const char* kstrchr(const char* s, int c);
const char* kstrrchr(const char* s, int c);
const char* kstrchrnul(const char* s, int c);

static inline int kisdigit(int c) {
  return c >= '0' && c <= '9';
}

static inline int kisalpha(int c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline int kisalnum(int c) {
  return kisdigit(c) || kisalpha(c);
}

static inline int kisspace(int c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' ||
         c == 'r';
}

static inline int kisprint(int c) {
  return c > 0x1f && c < 0x7f;
}

#endif
