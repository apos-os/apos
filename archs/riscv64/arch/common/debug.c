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
#include "arch/common/debug.h"

#include <stdint.h>

static long sbi_call(uint64_t eid, uint64_t fid, long* val_out,
                     uint64_t arg0, uint64_t arg1) {
  long error, val;
  asm volatile (
      "mv a0, %[arg0]\n\t"
      "mv a1, %[arg1]\n\t"
      "mv a7, %[eid]\n\t"
      "mv a6, %[fid]\n\t"
      "ecall\n\t"
      "mv %[error], a0\n\t"
      "mv %[val], a1\n\t"
      : [error] "=r"(error),
        [val] "=r"(val)
      : [arg0] "r"(arg0),
        [arg1] "r"(arg1),
        [eid] "r"(eid),
        [fid] "r"(fid));
  *val_out = val;
  return error;
}

void arch_debug_putc(char c) {
  long val;
  sbi_call(1, 0, &val, c, 0);
}
