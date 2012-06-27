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

#include <stdint.h>
#include <stdarg.h>

#include "common/kprintf.h"

static void outb(uint16_t port, uint16_t c) {
  __asm__(
        "mov %0, %%dx;"
        "mov %1, %%ax;"
        "outb %%ax, %%dx;"
        :: "r"(port), "r"(c) : "%dx", "%ax");
}

void klog(const char* s) {
  int i = 0;
  while (s[i]) {
    outb(0x37a, 0x04 | 0x08);
    outb(0x378, s[i]);
    outb(0x37a, 0x01);
    i++;
  }
}

void klogf(const char* fmt, ...) {
  char buf[1024];

  va_list args;
  va_start(args, fmt);
  kvsprintf(buf, fmt, args);
  va_end(args);

  klog(buf);
}
