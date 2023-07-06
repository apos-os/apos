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
#include "arch/memory/page_alloc.h"

void page_frame_alloc_init(memory_info_t* meminfo) {
  // TODO(riscv): implement
}

phys_addr_t page_frame_alloc(void) {
  // TODO(riscv): implement
  return 0;
}

void page_frame_free(phys_addr_t frame) {
  // TODO(riscv): implement
}

void page_frame_free_nocheck(phys_addr_t frame) {
  // TODO(riscv): implement
}

phys_addr_t page_frame_dma_alloc(size_t pages) {
  // TODO(riscv): implement
  return 0;
}
