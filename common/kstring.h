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

#include <stdint.h>

int kstrlen(const char* s);
int kstrcmp(const char* s1, const char* s2);
int kstrncmp(const char* s1, const char* s2, uint32_t n);

void* kmemset(void* s, int c, uint32_t n);
void* kmemcpy(void* dest, const void* src, uint32_t n);
int kmemcmp(const void* s1, const void* s2, uint32_t n);

char* kstrcpy(char* dst, const char* src);
char* kstrncpy(char* dst, const char* src, uint32_t n);

char *kstrcat(char *dest, const char *src);

const char* itoa(int32_t x);
const char* itoa_hex(int32_t x);

const char* utoa(uint32_t x);
const char* utoa_hex(uint32_t x);

// Note: these only support decimal.
int32_t atoi(const char* s);
uint32_t atou(const char* s);

const char* kstrchr(const char* s, int c);
const char* kstrrchr(const char* s, int c);
const char* kstrchrnul(const char* s, int c);

#endif
