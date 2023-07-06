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
#include "arch/syscall/context.h"

#include "arch/proc/user_context.h"

user_context_t syscall_extract_context(long retval) {
  // TODO(riscv): implement
  user_context_t context;
  context.dummy = 0;
  return context;
}

long syscall_get_result(const user_context_t* ctx) {
  // TODO(riscv): implement
  return 0;
}

void syscall_set_result(user_context_t* ctx, long retval) {
  // TODO(riscv): implement
}
