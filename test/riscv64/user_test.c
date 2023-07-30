// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#include "arch/memory/layout.h"
#include "arch/proc/user_context.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/types.h"
#include "memory/mmap.h"
#include "proc/fork.h"
#include "proc/signal/signal.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/kernel_tests.h"
#include "user/include/apos/mmap.h"

// Basic user test.
static const char kBasicUserCode[] = {
    0x13, 0x05, 0xe0, 0x00,  // li      a0,14
    0x93, 0x05, 0xb0, 0x07,  // li      a2,123
    0x73, 0x00, 0x00, 0x00,  // ecall
};

static void do_basic_user_test(void* arg) {
  void* addr;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addr));
  kmemcpy(addr, kBasicUserCode, sizeof(kBasicUserCode));

  user_context_t ctx;
  ctx.ctx.ra = 1;
  ctx.ctx.sp = 2;
  ctx.ctx.gp = 3;
  ctx.ctx.tp = 4;
  ctx.ctx.t0 = 5;
  ctx.ctx.t1 = 6;
  ctx.ctx.t2 = 7;
  ctx.ctx.s0 = 8;
  ctx.ctx.s1 = 9;
  ctx.ctx.a0 = 10;
  ctx.ctx.a1 = 11;
  ctx.ctx.a2 = 12;
  ctx.ctx.a3 = 13;
  ctx.ctx.a4 = 14;
  ctx.ctx.a5 = 15;
  ctx.ctx.a6 = 16;
  ctx.ctx.a7 = 17;
  ctx.ctx.s2 = 18;
  ctx.ctx.s3 = 19;
  ctx.ctx.s4 = 20;
  ctx.ctx.s5 = 21;
  ctx.ctx.s6 = 22;
  ctx.ctx.s7 = 23;
  ctx.ctx.s8 = 24;
  ctx.ctx.s9 = 25;
  ctx.ctx.s10 = 26;
  ctx.ctx.s11 = 27;
  ctx.ctx.t3 = 28;
  ctx.ctx.t4 = 29;
  ctx.ctx.t5 = 30;
  ctx.ctx.t6 = 31;
  ctx.ctx.address = (addr_t)addr;
  user_context_apply(&ctx);
  die("shouldn't get here");
}

void rsv64_user_test(void) {
  KTEST_SUITE_BEGIN("riscv64: user tests");

  KTEST_BEGIN("riscv64: basic user test");
  kpid_t child = proc_fork(do_basic_user_test, NULL);
  int status = -1;
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  KEXPECT_EQ(123, status);
}
