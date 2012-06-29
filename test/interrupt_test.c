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
#include "common/kprintf.h"
#include "test/ktest.h"

// Trigger an error interrupt, a non-error interrupt, and an IRQ, and make sure
// that we didn't clobber registers %eax, %ebx, or %edx across the calls.
void interrupt_clobber_test() {
  KTEST_SUITE_BEGIN("interrupt register clobbering");

  uint32_t eax, ebx, edx;
  KTEST_BEGIN("no-error interrupt");
  eax = 0xBAADF00D;
  ebx = 0xBAADF11D;
  edx = 0xBAADF22D;
  __asm__ __volatile__ (
      "movl %3, %%eax\n\t"
      "movl %4, %%ebx\n\t"
      "movl %5, %%edx\n\t"
      "int $0\n\t"
      "movl %%eax, %0\n\t"
      "movl %%ebx, %1\n\t"
      "movl %%edx, %2\n\t"
      : "=m"(eax), "=m"(ebx), "=m"(edx)
      : "m"(eax), "m"(ebx), "m"(edx)
      : "eax", "ebx", "edx");
  KEXPECT_EQ(0xBAADF00D, eax);
  KEXPECT_EQ(0xBAADF11D, ebx);
  KEXPECT_EQ(0xBAADF22D, edx);

  KTEST_BEGIN("error interrupt");
  eax = 0xBAADF00D;
  ebx = 0xBAADF11D;
  edx = 0xBAADF22D;
  __asm__ __volatile__ (
      "movl %3, %%eax\n\t"
      "movl %4, %%ebx\n\t"
      "movl %5, %%edx\n\t"
      // Fake setting up the stack for an interrupt.
      "pushf\n\t"
      "push %%cs\n\t"
      "push $post_int\n\t"  // resume at 'post_int' below
      "push $0xCC\n\t"  // fake the error number
      "jmp int11\n\t"
      "post_int:\n\t"
      "movl %%eax, %0\n\t"
      "movl %%ebx, %1\n\t"
      "movl %%edx, %2\n\t"
      : "=m"(eax), "=m"(ebx), "=m"(edx)
      : "m"(eax), "m"(ebx), "m"(edx)
      : "eax", "ebx", "edx");
  KEXPECT_EQ(0xBAADF00D, eax);
  KEXPECT_EQ(0xBAADF11D, ebx);
  KEXPECT_EQ(0xBAADF22D, edx);

  KTEST_BEGIN("IRQ interrupt");
  eax = 0xBAADF00D;
  ebx = 0xBAADF11D;
  edx = 0xBAADF22D;
  __asm__ __volatile__ (
      "movl %3, %%eax\n\t"
      "movl %4, %%ebx\n\t"
      "movl %5, %%edx\n\t"
      "int $0x20\n\t"
      "movl %%eax, %0\n\t"
      "movl %%ebx, %1\n\t"
      "movl %%edx, %2\n\t"
      : "=m"(eax), "=m"(ebx), "=m"(edx)
      : "m"(eax), "m"(ebx), "m"(edx)
      : "eax", "ebx", "edx");
  KEXPECT_EQ(0xBAADF00D, eax);
  KEXPECT_EQ(0xBAADF11D, ebx);
  KEXPECT_EQ(0xBAADF22D, edx);
}
