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
#include "arch/common/die.h"
#include <stdint.h>

#include "arch/dev/interrupts.h"
#include "archs/riscv64/internal/sbi.h"

void arch_die(void) {
  long unused;
  disable_interrupts();
  while (1) {
    rsv64_sbi_call(RSV64_SBI_EID_HSM, RSV64_SBI_FID_HSM_HART_STOP, &unused, 0,
                   0);
    // This _shouldn't_ return.
  }
}
