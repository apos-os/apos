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
#include "arch/proc/exec.h"

#include "arch/memory/layout.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/mmap.h"

// TODO(aoates): this shares a lot of code with the x86 version --- consolidate?
// TODO(aoates): update this to use the DMZ copy-to-user helpers --- this
// _should_ be safe (once exec is fixed to stop all other threads), but would be
// better not to.

#define MAX_ARGV_ENVP_SIZE (MEM_USER_STACK_SIZE_64 / 4)

#define KLOG(...) klogfm(KL_PROC, __VA_ARGS__)

_Static_assert(MEM_USER_STACK_SIZE_64 % PAGE_SIZE == 0,
               "MEM_USER_STACK_SIZE must be an even multiple of PAGE_SIZE");

_Static_assert(MEM_USER_STACK_BOTTOM_64 % PAGE_SIZE == 0,
               "MEM_USER_STACK_BOTTOM must be page aligned");

// Copy the given string table to the stack, updating the stack top pointer.
// A copy of the table (with updated pointers) will be placed near the original
// stack top, pointing to copies of all the strings located in the stack.  The
// actual address of the table copy will be stored in |table_out_ptr|.
static int copy_string_table(addr_t* stack_top_ptr, char* const table[],
                             addr_t* table_out_ptr) {
  KASSERT((*stack_top_ptr) % sizeof(addr_t) == 0);

  addr_t* table_copy = (addr_t*)(addr_t)(*stack_top_ptr);
  int copied = 0;

  // Make a copy of the table first.
  for (int i = 0; table[i] != NULL; ++i) {
    copied += sizeof(addr_t);
    if (copied >= MAX_ARGV_ENVP_SIZE) return -E2BIG;

    *(table_copy - i) = 0x0;
    (*stack_top_ptr) -= sizeof(addr_t);
  }

  // Final NULL entry.
  copied += sizeof(addr_t);
  if (copied >= MAX_ARGV_ENVP_SIZE) return -E2BIG;
  *((addr_t*)(addr_t)(*stack_top_ptr)) = 0x0;
  (*stack_top_ptr) -= sizeof(addr_t);

  *table_out_ptr = *stack_top_ptr;

  // Copy each string.
  for (int i = 0; table[i] != NULL; ++i) {
    const int len = kstrlen(table[i]);
    if (copied + len >= MAX_ARGV_ENVP_SIZE) return -E2BIG;
    (*stack_top_ptr) -= len + 1;
    kstrcpy((void*)(addr_t)(*stack_top_ptr), table[i]);
    ((addr_t*)(addr_t)(*table_out_ptr))[i] = (addr_t)(*stack_top_ptr);
  }

  // Align the stack top appropriately.  Align to next lowest word, then add a
  // padding word for good measure.
  // TODO(aoates): how do we do this in a platform-independent way?
  (*stack_top_ptr) -= sizeof(addr_t) + (*stack_top_ptr) % sizeof(addr_t);

  return 0;
}

bool arch_binary_supported(const load_binary_t* bin) {
  return (bin->arch == BIN_RISCV_64);
}

int arch_prep_exec(const load_binary_t* bin, char* const argv[],
                   char* const envp[], user_context_t* ctx) {
  KASSERT(bin->arch == BIN_RISCV_64);

  // Create the stack.
  void* stack_addr_out;
  int result = do_mmap((void*)MEM_USER_STACK_BOTTOM_64, MEM_USER_STACK_SIZE_64,
                       KPROT_READ | KPROT_WRITE,
                       KMAP_PRIVATE | KMAP_FIXED | KMAP_ANONYMOUS,
                       -1, 0, &stack_addr_out);
  if (result) {
    KLOG(INFO, "exec error: couldn't create mapping for kernel stack: %s\n",
         errorname(-result));
    return result;
  }

  // Copy argv and envp to the new stack.
  addr_t stack_top =
      (MEM_USER_STACK_BOTTOM_64 + MEM_USER_STACK_SIZE_64 - sizeof(addr_t));
  addr_t argv_addr = 0x0;
  result = copy_string_table(&stack_top, argv, &argv_addr);
  if (result) {
    return result;
  }
  addr_t envp_addr = 0x0;
  result = copy_string_table(&stack_top, envp, &envp_addr);
  if (result) {
    return result;
  }

  kmemset(ctx, 0, sizeof(user_context_t));
  ctx->ctx.sp = stack_top;
  ctx->ctx.a0 = argv_addr;
  ctx->ctx.a1 = envp_addr;
  ctx->ctx.address = bin->entry;

  return 0;
}
