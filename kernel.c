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

const uint32_t kScreenWidth = 80;
const uint32_t kScreenHeight = 24;

void print(const char* msg) {
   unsigned char* videoram = (char *)0xB8000;
   uint32_t i, j;
   for (i = 0; i < kScreenWidth * kScreenHeight; ++i) {
     videoram[i*2] = ' ';
     videoram[i*2+1] = 0x07;
   }

   i = 0;
   while (*msg) {
     if (*msg == '\n') {
       i = ((i / kScreenWidth) + 1) * kScreenWidth - 1;
     } else {
       videoram[i*2] = *msg;
       videoram[i*2+1] = 0x07; /* light grey (7) on black (0). */
     }
     ++msg;
     ++i;
   }
}

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

  gdt_init();

  itoa_test();
}

void itoa_test() {
  char buf[1700];
  buf[0] = '\0';

  kstrcat(buf, "itoa() test:\n");
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
  print(buf);
}
