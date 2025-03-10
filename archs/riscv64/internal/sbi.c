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
#include "archs/riscv64/internal/sbi.h"

long rsv64_sbi_call(uint64_t eid, uint64_t fid, long* val_out, uint64_t arg0,
                    uint64_t arg1) {
  // Force arguments into specific registers.
  register uint64_t a0 asm ("a0") = arg0;
  register uint64_t a1 asm ("a1") = arg1;
  register uint64_t a7 asm ("a7") = eid;
  register uint64_t a6 asm ("a6") = fid;
  (void)a0;
  (void)a1;
  (void)a7;
  (void)a6;
  asm volatile(
      "ecall\n\t"
      : "+r"(a0), "+r"(a1)
      : "r"(a7), "r"(a6));
  long error = a0;
  long val = a1;
  if (val_out) *val_out = val;
  return error;
}
