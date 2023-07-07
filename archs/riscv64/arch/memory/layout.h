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
#ifndef APOO_ARCHS_RISCV64_ARCH_MEMORY_LAYOUT_H
#define APOO_ARCHS_RISCV64_ARCH_MEMORY_LAYOUT_H

// TODO(riscv): confirm and tweak these for riscv64.

// riscv64 memory layout:
// +-----------------------------------------+------+----------------------+
// |                  Range                  | Size |     Description      |
// +-----------------------------------------+------+----------------------+
// | 0x0000000000000000 - 0x0000007FFFFFFFFF | 512G | User mode addresses  |
// | 0x0000008000000000 - 0xFFFFFF7FFFFFFFFF |      | Unusable addresses   |
// | 0xFFFFFF8000000000 - 0xFFFFFFEFFFFFFFFF | 448G | Kernel (unused)      |
// | 0xFFFFFFF000000000 - 0xFFFFFFF0FFFFFFFF | 4G   | Physical memory map  |
// | 0xFFFFFFFF00000000 - 0xFFFFFFFF7FFFFFFF | 2G   | Kernel heap          |
// | 0xFFFFFFFF80000000 - 0xFFFFFFFFFFFFFFFF | 2G   | Kernel (code + data) |
// |   0xFFFFFFFF88000000+ -> kernel image   |      |                      |
// +-----------------------------------------+------+----------------------+

#define PAGE_SIZE          0x00001000
#define PAGE_INDEX_MASK    0xFFFFFFFFFFFFF000
#define PAGE_OFFSET_MASK   0x0000000000000FFF

#define MIN_GLOBAL_MAPPING_SIZE PAGE_SIZE

// The first and last mappable addresses.
#define MEM_FIRST_MAPPABLE_ADDR PAGE_SIZE
#define MEM_LAST_USER_MAPPABLE_ADDR 0x0000007FFFFFFFFF
#define MEM_LAST_MAPPABLE_ADDR      0xFFFFFFFFFFFFFFFF

// Location and size of the user-mode process stack.
#define MEM_USER_STACK_SIZE_64 (8 * 1024 * 1024)  // 8MB
#define MEM_USER_STACK_BOTTOM_64 \
    (MEM_LAST_USER_MAPPABLE_ADDR + 1 - MEM_USER_STACK_SIZE_64)

// Internal platform-specific constants.
#define RSV64_FIRST_KERNEL_ADDR      0xFFFFFF8000000000
#define RSV64_FIRST_USED_KERNEL_ADDR 0xFFFFFFF000000000
#define RSV64_KPHYSMAP_ADDR          0xFFFFFFF000000000
#define RSV64_KPHYSMAP_LEN           0x0000000100000000
#define RSV64_HEAP_START             0xFFFFFFFF00000000
#define RSV64_HEAP_LEN               0x0000000080000000

#endif
