// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_CORE_LOADER_ELF64_H
#define APOO_OS_CORE_LOADER_ELF64_H

#include <stddef.h>

#include "proc/load/elf-internal.h"
#include "os/core/loader/load-binary.h"

// Checks the validity of an Elf64_Ehdr.  Returns 0 if it's valid (i.e., we can
// load the file with that header).
int elf64_check_header(const Elf64_Ehdr* header);

int elf64_load(int fd, load_binary_t** binary_out);

// Parsed info from the PT_DYNAMIC segment of an ELF file.
typedef struct {
  const Elf64_Dyn* dyn_array;  // All dynamic entries.
  const Elf64_Rela* rela;
  size_t rela_count;
} elf64_dyninfo_t;

int elf64_parse_dynamic(uint64_t base_addr, const Elf64_Ehdr* ehdr,
                        elf64_dyninfo_t* dyn);

#endif
