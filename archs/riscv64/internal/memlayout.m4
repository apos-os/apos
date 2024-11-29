dnl Copyright 2023 Andrew Oates.  All Rights Reserved.
dnl
dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.
divert(-1)

define(`fail', `errprint(`$1
')m4exit(1)')
define(`PROVIDE',
  ifelse(gentype, `asm', ``.set $1, $2'',
         gentype, `ld', ``$1 = $2;'',
         gentype, `c', ``#define $1 $2'',
         `fail(`Invalid gentype')'))

divert(1)dnl
dnl
dnl
PROVIDE(RSV64_FIRST_KERNEL_ADDR,       0xFFFFFF8000000000)
PROVIDE(RSV64_FIRST_USED_KERNEL_ADDR,  0xFFFFFFF000000000)
PROVIDE(RSV64_KPHYSMAP_ADDR,           0xFFFFFFF000000000)
PROVIDE(RSV64_KPHYSMAP_LEN,            0x0000000800000000)
PROVIDE(RSV64_HEAP_START,              0xFFFFFFFF00000000)
PROVIDE(RSV64_HEAP_LEN,                0x0000000080000000)
PROVIDE(RSV64_KERNEL_VIRT_OFFSET,      0xFFFFFFFF00000000)
dnl
dnl Physical address of the start of the general kernel section (_not_
dnl specifically where the kernel itself sits, but the area it is linked).
PROVIDE(RSV64_KERNEL_PHYS_ADDR,        0x0000000080000000)
dnl
dnl How much scratch space to reserve at the bottom (highest addresses) of every
dnl kernel mode stack.
PROVIDE(RSV64_KSTACK_SCRATCH_NBYTES, -24)
dnl
dnl How big to make the double-fault stack.
PROVIDE(RSV64_DBLFAULT_STACK_SIZE, 4096)
