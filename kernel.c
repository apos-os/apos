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

#include "gdt.h"
#include "kstring.h"
#include "paging.h"

const uint32_t kScreenWidth = 80;
const uint32_t kScreenHeight = 24;

static unsigned char* const videoram = (char *)0xB8000;
static uint32_t cursor = 0;

void clear() {
  cursor = 0;
  uint32_t i, j;
  for (i = 0; i < kScreenWidth * kScreenHeight; ++i) {
    videoram[i*2] = ' ';
    videoram[i*2+1] = 0x07;
  }
}

void print(const char* msg) {
  int i = 0;
  while (*msg) {
    if (*msg == '\n') {
      cursor = ((cursor / kScreenWidth) + 1) * kScreenWidth - 1;
    } else {
      videoram[cursor*2] = *msg;
      videoram[cursor*2+1] = 0x07; /* light grey (7) on black (0). */
    }
    ++msg;
    ++cursor;
  }
}

void itoa_test();
void paging_test();

void kmain(void) {
   extern uint32_t magic;
   extern void *mbd;

   if ( magic != 0x2BADB002 )
   {
      /* Something went not according to specs. Print an error */
      /* message and halt, but do *not* rely on the multiboot */
      /* data structure. */
   }

   /* You could either use multiboot.h */
   /* (http://www.gnu.org/software/grub/manual/multiboot/multiboot.html#multiboot_002eh) */
   /* or do your offsets yourself. The following is merely an example. */
   //char * boot_loader_name =(char*) ((long*)mbd)[16];

  clear();
  print("APOO\n");
  print("kmain: 0x");
  print(itoa_hex((uint32_t)&kmain));
  print("\nitoa_test: 0x");
  print(itoa_hex((uint32_t)&itoa_test));
  print("\npaging_init: 0x");
  print(itoa_hex((uint32_t)(&paging_init)));

  paging_test();
  itoa_test();
}

void itoa_test() {
  char buf[1700];
  buf[0] = '\0';

  kstrcat(buf, "\n\nitoa() test:\n");
  kstrcat(buf, "------------\n");
  kstrcat(buf, "0: '");
  kstrcat(buf, itoa(0));
  kstrcat(buf, "'\n");

  kstrcat(buf, "1: '");
  kstrcat(buf, itoa(1));
  kstrcat(buf, "'\n");

  kstrcat(buf, "10: '");
  kstrcat(buf, itoa(10));
  kstrcat(buf, "'\n");

  kstrcat(buf, "100: '");
  kstrcat(buf, itoa(100));
  kstrcat(buf, "'\n");

  kstrcat(buf, "123: '");
  kstrcat(buf, itoa(123));
  kstrcat(buf, "'\n");

  kstrcat(buf, "1234567890: '");
  kstrcat(buf, itoa(1234567890));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0x0: '");
  kstrcat(buf, itoa_hex(0x0));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0x1: '");
  kstrcat(buf, itoa_hex(0x1));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0xABCDEF0: '");
  kstrcat(buf, itoa_hex(0xABCDEF0));
  kstrcat(buf, "'\n");

  print(buf);
}

extern uint32_t KERNEL_START_SYMBOL;
extern uint32_t KERNEL_END_SYMBOL;
void paging_test() {
  char buf[1700];
  kstrcpy(buf, "\n\npaging test:\n");
  kstrcat(buf, "------------\n");
  kstrcat(buf, "KERNEL_START: 0x");
  kstrcat(buf, itoa_hex(KERNEL_START_SYMBOL));
  kstrcat(buf, "\n&KERNEL_START: 0x");
  kstrcat(buf, itoa_hex(&KERNEL_START_SYMBOL));
  kstrcat(buf, "\nKERNEL_END: 0x");
  kstrcat(buf, itoa_hex(KERNEL_END_SYMBOL));
  kstrcat(buf, "\n&KERNEL_END: 0x");
  kstrcat(buf, itoa_hex(&KERNEL_END_SYMBOL));
  print(buf);
}
