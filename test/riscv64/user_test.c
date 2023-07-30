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
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "user/include/apos/mmap.h"

// Generating these:
//  riscv64-elf-as -o /tmp/test.o test/riscv64/basic_user.s
//  riscv64-elf-objdump -d --no-addresses --section=.text /tmp/test.o | sed //  's/#.*//'
//  '<,'>s/^\s*\(..\)\(..\)\(..\)\(..\)\s*/0x\4, 0x\3, 0x\2, 0x\1, \/\/ /g

// Basic user test.
static const char kBasicUserCode[] = {
    0x13, 0x05, 0x40, 0x06,  // li      a0,100
    0x93, 0x05, 0x10, 0x00,  // li      a1,1
    0x13, 0x06, 0x20, 0x00,  // li      a2,2
    0x93, 0x06, 0x30, 0x00,  // li      a3,3
    0x13, 0x07, 0x40, 0x00,  // li      a4,4
    0x93, 0x07, 0x50, 0x00,  // li      a5,5
    0x13, 0x08, 0x60, 0x00,  // li      a6,6
    0x93, 0x08, 0x70, 0x00,  // li      a7,7
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x93, 0x05, 0x05, 0x00,  // mv      a1,a0
    0x13, 0x05, 0xe0, 0x00,  // li      a0,14
    0x73, 0x00, 0x00, 0x00,  // ecall
};

static const char kSegfaultCode[] = {
    0x13, 0x05, 0x30, 0x12,  // li      a0,291
    0x67, 0x00, 0x05, 0x00,  // jr      a0
};

static void* _map_code(const char* buf, size_t len) {
  void* addr;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &addr));
  kmemcpy(addr, buf, len);
  return addr;
}

// Creates a stack mapping, sets up a stub frame, and returns the stack top.
static uint64_t* make_stack(void) {
  void* stack_block;
  KEXPECT_EQ(0, do_mmap(NULL, PAGE_SIZE, MEM_PROT_ALL,
                        KMAP_ANONYMOUS | KMAP_PRIVATE, -1, 0, &stack_block));
  uint64_t* stack = (uint64_t*)((addr_t)stack_block + PAGE_SIZE);
  *(--stack) = 0;
  *(--stack) = 0;
  return stack;
}

#define MAP_CODE(buf) _map_code(buf, sizeof(buf))

static void do_basic_user_test(void* arg) {
  void* addr = MAP_CODE(kBasicUserCode);

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

static void do_segfault_test(void* arg) {
  void* addr = MAP_CODE(kSegfaultCode);

  user_context_t ctx;
  kmemset(&ctx, 0, sizeof(ctx));
  ctx.ctx.address = (addr_t)addr;
  user_context_apply(&ctx);
  die("shouldn't get here");
}

static const char kSigactionTest[] = {
    0x13, 0x01, 0x01, 0xff,  // addi    sp,sp,-16
    0x23, 0x30, 0xa1, 0x00,  // sd      a0,0(sp)
    0x23, 0x24, 0x01, 0x00,  // sw      zero,8(sp)
    0x23, 0x26, 0x01, 0x00,  // sw      zero,12(sp)
    0x93, 0x04, 0x85, 0x3e,  // addi    s1,a0,1000
    0x13, 0x03, 0xb0, 0x07,  // li      t1,123
    0x23, 0xb0, 0x64, 0x00,  // sd      t1,0(s1)
    0x13, 0x05, 0x40, 0x01,  // li      a0,20
    0x93, 0x05, 0x30, 0x01,  // li      a1,19
    0x13, 0x06, 0x01, 0x00,  // mv      a2,sp
    0x93, 0x06, 0x00, 0x00,  // li      a3,0
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x13, 0x05, 0x00, 0x01,  // li      a0,16
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x93, 0x05, 0x05, 0x00,  // mv      a1,a0
    0x13, 0x05, 0x30, 0x01,  // li      a0,19
    0x13, 0x06, 0x30, 0x01,  // li      a2,19
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x13, 0x05, 0xe0, 0x00,  // li      a0,14
    0x83, 0xb5, 0x04, 0x00,  // ld      a1,0(s1)
    0x73, 0x00, 0x00, 0x00,  // ecall
};

static const char kSigactionHandler[] = {
    0x97, 0x04, 0x00, 0x00,  // auipc   s1,0x0
    0x93, 0x84, 0x84, 0x3e,  // addi    s1,s1,1000
    0x13, 0x01, 0x01, 0xff,  // addi    sp,sp,-16
    0x37, 0x73, 0xf5, 0xfe,  // lui     t1,0xfef57
    0x1b, 0x03, 0x53, 0xef,  // addiw   t1,t1,-267
    0x13, 0x13, 0xc3, 0x00,  // slli    t1,t1,0xc
    0x13, 0x03, 0xf3, 0x6e,  // addi    t1,t1,1775
    0x13, 0x13, 0xc3, 0x00,  // slli    t1,t1,0xc
    0x13, 0x03, 0xf3, 0x56,  // addi    t1,t1,1391
    0x13, 0x13, 0xd3, 0x00,  // slli    t1,t1,0xd
    0x13, 0x03, 0xd3, 0xea,  // addi    t1,t1,-339
    0x23, 0x30, 0x61, 0x00,  // sd      t1,0(sp)
    0x23, 0x34, 0x61, 0x00,  // sd      t1,8(sp)
    0x13, 0x05, 0x40, 0x06,  // li      a0,100
    0x93, 0x05, 0x20, 0x00,  // li      a1,2
    0x13, 0x06, 0x30, 0x00,  // li      a2,3
    0x93, 0x06, 0x40, 0x00,  // li      a3,4
    0x13, 0x07, 0x50, 0x00,  // li      a4,5
    0x93, 0x07, 0x60, 0x00,  // li      a5,6
    0x13, 0x08, 0x70, 0x00,  // li      a6,7
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x23, 0xb0, 0xa4, 0x00,  // sd      a0,0(s1)
    0x13, 0x01, 0x01, 0x01,  // addi    sp,sp,16
    0x67, 0x80, 0x00, 0x00,  // ret
};

static void do_sigaction_test(void* arg) {
  void* addr = MAP_CODE(kSigactionTest);
  void* handler = MAP_CODE(kSigactionHandler);
  void* stack = make_stack();

  user_context_t ctx;
  kmemset(&ctx, 0, sizeof(ctx));
  ctx.ctx.a0 = (addr_t)handler;
  ctx.ctx.s0 = (addr_t)stack + 16;
  ctx.ctx.sp = (addr_t)stack;
  ctx.ctx.address = (addr_t)addr;
  user_context_apply(&ctx);
  die("shouldn't get here");
}

static const char kForkTestCode[] = {
    0x13, 0x01, 0x01, 0xfe,  // addi    sp,sp,-32
    0x23, 0x3c, 0x11, 0x00,  // sd      ra,24(sp)
    0x23, 0x38, 0x81, 0x00,  // sd      s0,16(sp)
    0x13, 0x04, 0x01, 0x02,  // addi    s0,sp,32
    0x13, 0x05, 0xd0, 0x00,  // li      a0,13
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x63, 0x18, 0x05, 0x00,  // bnez    a0,<.Lparent>
    0x13, 0x05, 0xe0, 0x00,  // li      a0,14
    0x93, 0x05, 0x80, 0x00,  // li      a1,8
    0x73, 0x00, 0x00, 0x00,  // ecall

    // <.Lparent>:
    0x93, 0x04, 0x05, 0x00,  // mv      s1,a0
    0x13, 0x05, 0x90, 0x02,  // li      a0,41
    0x93, 0x05, 0x01, 0x00,  // mv      a1,sp
    0x73, 0x00, 0x00, 0x00,  // ecall
    0x83, 0x35, 0x01, 0x00,  // ld      a1,0(sp)
    0x93, 0x85, 0x15, 0x00,  // addi    a1,a1,1
    0x13, 0x05, 0xe0, 0x00,  // li      a0,14
    0x73, 0x00, 0x00, 0x00,  // ecall
};

static void do_fork_test(void* arg) {
  void* addr = MAP_CODE(kForkTestCode);
  void* stack = make_stack();

  user_context_t ctx;
  kmemset(&ctx, 0, sizeof(ctx));
  ctx.ctx.s0 = (addr_t)stack + 16;  // fp
  ctx.ctx.sp = (addr_t)stack;
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
  KEXPECT_EQ(0xd04f5e82, status);


  KTEST_BEGIN("riscv64: segfault user test");
  child = proc_fork(do_segfault_test, NULL);
  status = -1;
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGSEGV, WTERMSIG(status));


  // TODO(riscv): properly support 64-bit userspace syscalls (the test passes
  // even with the incorrect 32-bit conversions because they're linked at low
  // addresses).
  KTEST_BEGIN("riscv64: sigaction user test");
  child = proc_fork(do_sigaction_test, NULL);
  status = -1;
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  KEXPECT_EQ(0x4bf779a4, status);


  KTEST_BEGIN("riscv64: basic fork user test");
  child = proc_fork(do_fork_test, NULL);
  status = -1;
  KEXPECT_EQ(child, proc_waitpid(child, &status, 0));
  KEXPECT_EQ(9, status);
}
