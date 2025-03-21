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
#ifndef APOO_ARCHS_RISCV64_INTERNAL_SBI_H
#define APOO_ARCHS_RISCV64_INTERNAL_SBI_H

#include <stdint.h>

#define RSV64_SBI_EID_LEGACY_PUTCHAR 0x1
#define RSV64_SBI_EID_HSM 0x48534D
#define RSV64_SBI_EID_TIME 0x54494D45

#define RSV64_SBI_FID_HSM_HART_STOP 0x1

// Makes an SBI call to the SEE.  Returns the error code and sets the value
// returned (if any) to *val_out.  If the SBI call doesn't return a value,
// *val_out is unspecified.
long rsv64_sbi_call(uint64_t eid, uint64_t fid, long* val_out, uint64_t arg0,
                    uint64_t arg1);

// SBI calls.
#define rsv64_sbi_set_timer(stime_value) \
  rsv64_sbi_call(RSV64_SBI_EID_TIME, 0, NULL, stime_value, 0)

#endif
