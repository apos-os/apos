// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

// "template" version of the binary loading code, that can be instantiated for
// either 32-bit or 64-bit code by defining NUM_BITS.

#include "common/config.h"

#define _CONCAT2(a, b, c) a##b##c
#define _CONCAT(a, b, c) _CONCAT2(a, b, c)

#define BIN_ADDR_T _CONCAT(addr_, NUM_BITS, _t)
#define COPY_STRING_TABLE _CONCAT(copy_string_table_, NUM_BITS, )
#define PREP_FUNC _CONCAT(x86_prep_exec_, NUM_BITS, )

#define STK_SIZE _CONCAT(MEM_USER_STACK_SIZE_, NUM_BITS, )
#define STK_BOTTOM _CONCAT(MEM_USER_STACK_BOTTOM_, NUM_BITS, )

#define MAX_ARGV_ENVP_SIZE (STK_SIZE / 4)

_Static_assert(STK_SIZE % PAGE_SIZE == 0,
               "MEM_USER_STACK_SIZE must be an even multiple of PAGE_SIZE");

_Static_assert(STK_BOTTOM % PAGE_SIZE == 0,
               "MEM_USER_STACK_BOTTOM must be page aligned");

// Copy the given string table to the stack, updating the stack top pointer.
// A copy of the table (with updated pointers) will be placed near the original
// stack top, pointing to copies of all the strings located in the stack.  The
// actual address of the table copy will be stored in |table_out_ptr|.
static int COPY_STRING_TABLE(BIN_ADDR_T* stack_top_ptr, char* const table[],
                             BIN_ADDR_T* table_out_ptr) {
  KASSERT((*stack_top_ptr) % sizeof(BIN_ADDR_T) == 0);

  BIN_ADDR_T* table_copy = (BIN_ADDR_T*)(addr_t)(*stack_top_ptr);
  int copied = 0;

  // Make a copy of the table first.
  for (int i = 0; table[i] != NULL; ++i) {
    copied += sizeof(BIN_ADDR_T);
    if (copied >= MAX_ARGV_ENVP_SIZE) return -E2BIG;

    *(table_copy - i) = 0x0;
    (*stack_top_ptr) -= sizeof(BIN_ADDR_T);
  }

  // Final NULL entry.
  copied += sizeof(BIN_ADDR_T);
  if (copied >= MAX_ARGV_ENVP_SIZE) return -E2BIG;
  *((BIN_ADDR_T*)(addr_t)(*stack_top_ptr)) = 0x0;
  (*stack_top_ptr) -= sizeof(BIN_ADDR_T);

  *table_out_ptr = *stack_top_ptr;

  // Copy each string.
  for (int i = 0; table[i] != NULL; ++i) {
    const int len = kstrlen(table[i]);
    if (copied + len >= MAX_ARGV_ENVP_SIZE) return -E2BIG;
    (*stack_top_ptr) -= len + 1;
    kstrcpy((void*)(addr_t)(*stack_top_ptr), table[i]);
    ((BIN_ADDR_T*)(addr_t)(*table_out_ptr))[i] = (BIN_ADDR_T)(*stack_top_ptr);
  }

  // Align the stack top appropriately.  Align to next lowest word, then add a
  // padding word for good measure.
  // TODO(aoates): how do we do this in a platform-independent way?
  (*stack_top_ptr) -= sizeof(BIN_ADDR_T) + (*stack_top_ptr) % sizeof(BIN_ADDR_T);

  return 0;
}

static int PREP_FUNC(const load_binary_t* bin, char* const argv[],
                     char* const envp[], user_context_t* ctx) {
  KASSERT(bin->arch == BIN_X86_32);

  // Create the stack.
  void* stack_addr_out;
  int result = do_mmap((void*)STK_BOTTOM, STK_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                       -1, 0, &stack_addr_out);
  if (result) {
    KLOG(INFO, "exec error: couldn't create mapping for kernel stack: %s\n",
         errorname(-result));
    return result;
  }

  // Copy argv and envp to the new stack.
  BIN_ADDR_T stack_top = (STK_BOTTOM + STK_SIZE - sizeof(BIN_ADDR_T));
  BIN_ADDR_T argv_addr = 0x0;
  result = COPY_STRING_TABLE(&stack_top, argv, &argv_addr);
  if (result) {
    return result;
  }
  BIN_ADDR_T envp_addr = 0x0;
  result = COPY_STRING_TABLE(&stack_top, envp, &envp_addr);
  if (result) {
    return result;
  }

  // Push argv and envp onto the stack to pass to the program.
  stack_top -= stack_top % sizeof(BIN_ADDR_T);
  *(BIN_ADDR_T*)(addr_t)(stack_top -= sizeof(BIN_ADDR_T)) = envp_addr;
  *(BIN_ADDR_T*)(addr_t)(stack_top -= sizeof(BIN_ADDR_T)) = argv_addr;
  *(BIN_ADDR_T*)(addr_t)(stack_top -= sizeof(BIN_ADDR_T)) = 0x0;  // Fake return address

  kmemset(ctx, 0, sizeof(user_context_t));
  ctx->type = USER_CONTEXT_INTERRUPT;
#if ARCH == ARCH_i586
  ctx->esp = stack_top;
  ctx->eip = bin->entry;
  asm volatile(
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(ctx->eflags));
  ctx->eflags |= IF_FLAG;
#elif ARCH == ARCH_x86_64
  ctx->rsp = stack_top;
  ctx->rip = bin->entry;
  asm volatile(
      "pushf\n\t"
      "pop %0\n\t"
      : "=r"(ctx->rflags));
  ctx->rflags |= IF_FLAG;
#else
#  error bad ARCH in x86 code
#endif

  return 0;
}

#undef MAX_ARGV_ENVP_SIZE
#undef STK_SIZE
#undef STK_BOTTOM
#undef BIN_ADDR_T
#undef COPY_STRING_TABLE
#undef PREP_FUNC
