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

#include "arch/common/debug.h"
#include "common/config.h"
#include "common/endian.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/devicetree/dtb.h"
#include "memory/memory.h"

#include "common/kprintf.h"

_Static_assert(ARCH == ARCH_riscv64, "bad ARCH");
_Static_assert(ARCH_IS_64_BIT, "ARCH_IS_64_BIT should be set");

extern void kmain(memory_info_t* meminfo);

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

  klog("Booting APOS on riscv64\n");

  fdt_header_t fdt_header;
  dtfdt_validate(fdt, &fdt_header);
  dtfdt_print(fdt, &fdt_header, true, &klog);

  // We can't ever return or we'll page fault!
  while(1);
}
