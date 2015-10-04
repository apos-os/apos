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

#include "arch/dev/interrupts.h"
#include "arch/memory/layout.h"
#include "arch/proc/exec.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/mmap.h"

#define MAX_ARGV_ENVP_SIZE (MEM_USER_STACK_SIZE / 4)

#define KLOG(...) klogfm(KL_PROC, __VA_ARGS__)

typedef uint32_t addr_32_t;

#define NUM_BITS 32
#include "archs/x86-common/internal/proc/exec.tpl.c"
#undef NUM_BITS

int arch_prep_exec(const load_binary_t* bin, char* const argv[],
                   char* const envp[], user_context_t* ctx) {
  KASSERT(arch_binary_supported(bin));

  switch (bin->arch) {
    case BIN_X86_32:
      return x86_prep_exec_32(bin, argv, envp, ctx);
    default:
      KLOG(FATAL, "unsupported architecture: %d\n", bin->arch);
  }

  return -EINVAL;  // Shouldn't get here.
}

