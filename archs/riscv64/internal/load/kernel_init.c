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

#include <stddef.h>
#include <stdint.h>

#include "common/config.h"
#include "common/endian.h"
#include "common/kstring.h"
#include "dev/devicetree/dtb.h"
#include "memory/memory.h"

#include "common/kprintf.h"

_Static_assert(ARCH == ARCH_riscv64, "bad ARCH");
_Static_assert(ARCH_IS_64_BIT, "ARCH_IS_64_BIT should be set");

extern void kmain(memory_info_t* meminfo);

struct sbiret {
  long error;
  long value;
};

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

static void debug_putc(char c) {
  long val;
  sbi_call(1, 0, &val, c, 0);
}

static void debug_puts(const char* s) {
  while (*s) {
    debug_putc(*s);
    s++;
  }
}

// Glue function in between 'all-physical' setup code and 'all-virtual' kernel
// code.  Tears down temporary mappings set up by paging initialization and
// finishes transfer to fully-virtual memory space.
//
// Unlike everything else in load/, is linked at it's VIRTUAL address.  It's
// invoked after paging is setup, at which point we're running completely in
// higher-half mode.
void kinit(int hart_id, const void* fdt) {
  // TODO(riscv): copy the FDT to virtual memory and unmap the physical
  // identity mapping.

  debug_puts("Booted APOS on riscv64\n");

  // We can't ever return or we'll page fault!
  while(1);
}
