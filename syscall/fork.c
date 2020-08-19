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

#include "arch/syscall/context.h"
#include "common/errno.h"
#include "memory/kmalloc.h"
#include "proc/fork.h"
#include "syscall/fork.h"

static void proc_fork_syscall_trampoline(void* arg) {
  user_context_t* context_ptr = (user_context_t*)arg;
  user_context_t context = *context_ptr;
  kfree(context_ptr);

  user_context_apply(&context);
}

kpid_t proc_fork_syscall() {
  user_context_t* context_ptr =
      (user_context_t*)kmalloc(sizeof(user_context_t));
  if (!context_ptr) return -ENOMEM;

  *context_ptr = syscall_extract_context(0 /* return 0 in the child */);
  int result = proc_fork(&proc_fork_syscall_trampoline, context_ptr);
  if (result < 0) {
    kfree(context_ptr);
  }
  return result;
}
