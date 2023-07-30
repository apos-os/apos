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

#include "arch/proc/user_context.h"
#include "arch/syscall/context.h"
#include "proc/kthread-internal.h"
#include "proc/user_prepare.h"
#include "syscall/syscall_dispatch.h"

static user_context_t syscall_extract_context_tramp(void* arg) {
  return syscall_extract_context(*(long*)arg);
}

long x86_syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
                          long arg4, long arg5, long arg6) {
  const long result =
      syscall_dispatch(syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);
  proc_prep_user_return(&syscall_extract_context_tramp, (void*)&result,
                        &kthread_current_thread()->syscall_ctx);

  // Don't do anything here!  After we call proc_prep_user_return(), we may
  // never return.
  return result;
}
