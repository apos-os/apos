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

// Parsed info from the program header segment.
typedef struct {
  const Elf64_Dyn* dyn_array;
  // The minimum and maximum addresses of all LOAD segments.
  uint64_t load_min;
  uint64_t load_max;
} elf64_phdr_info_t;

// Parsed info from the PT_DYNAMIC segment of an ELF file.
typedef struct {
  const Elf64_Dyn* dyn_array;  // All dynamic entries.
  const char* soname;
  const char* strtab;
  const Elf64_Rela* rela;
  size_t rela_count;
} elf64_dyninfo_t;

// Mode to read the file in.  This determines whether we look for data as a data
// offset from the start of the file (if the whole file is mmap'd in), or if we
// look for it at the appropriate vaddr (if the ELF file is already loaded).
typedef enum {
  ELF_MAPPED_FILE = 1,
  ELF_MAPPED_LOADED = 2,
} elf64_map_type_t;

// Find the PT_DYNAMIC array in the given ELF image and return a memory address
// that can be used to read it.
int elf64_parse_phdr(uint64_t base_addr, const Elf64_Ehdr* ehdr,
                     elf64_map_type_t mapping, elf64_phdr_info_t* phdr);

// Parse the PT_DYNAMIC section into |dyninfo|.
int elf64_parse_dynamic(uint64_t base_addr, const Elf64_Ehdr* ehdr,
                        const elf64_phdr_info_t* phdr,
                        elf64_dyninfo_t* dyninfo);

#endif
