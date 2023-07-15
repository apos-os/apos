// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include "arch/memory/layout.h"
#include "arch/memory/page_map.h"

void page_frame_map_virtual(addr_t virt, phys_addr_t phys, int prot,
                            mem_access_t access, int flags) {
  // TODO(riscv): implement
}

void page_frame_remap_virtual(addr_t virt, int prot, mem_access_t access,
                              int flags) {
  // TODO(riscv): implement
}

void page_frame_unmap_virtual(addr_t virt) {
  // TODO(riscv): implement
}

void page_frame_unmap_virtual_range(addr_t virt, addrdiff_t length) {
  // TODO(riscv): implement
}

page_dir_ptr_t page_frame_alloc_directory(void) {
  // TODO(riscv): implement
  return 0;
}

void page_frame_free_directory(page_dir_ptr_t page_directory) {
  // TODO(riscv): implement
}

void page_frame_init_global_mapping(addr_t addr, addr_t length) {
  // TODO(riscv): implement
}

void page_frame_link_global_mapping(page_dir_ptr_t target,
                                    addr_t addr, addr_t length) {
  // TODO(riscv): implement
}
