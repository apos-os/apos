// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_CORE_LOADER_LIB_H
#define APOO_OS_CORE_LOADER_LIB_H

#include "os/core/loader/elf64.h"
#include "os/core/loader/gnu_hash.h"
#include "proc/load/elf-internal.h"

struct load_binary;

typedef enum {
  LIB_NEEDED,  // We need the library but haven't found it yet.
  LIB_FOUND,   // The library has be identified.
  LIB_LOADED,  // The library is loaded into memory.
} lib_state_t;

// A library to be loaded.
typedef struct lib {
  lib_state_t state;
  const char* so_name;
  const char* path;  // If we've found a matching library.
  int fd;

  // ELF64 data, if currently mapped.
  const Elf64_Ehdr* ehdr;
  elf64_dyninfo_t dyn;

  gnu_hash_section_t gnuhash;

  struct load_binary* bin;
  struct lib* next;  // The next library in global load order.
} lib_t;

// Global context of the load.
typedef struct {
  lib_t* libs;  // Libraries in global order.  The first is the binary itself.
  lib_t* last_lib;

  // The next available address for mapping a shared object.
  uint64_t next_load_addr;
} ctx_t;

// Resolves all libraries transitively needed by the current loading binary.
int find_libs(ctx_t* ctx);

// Once all libraries are resolved and opened, load them all into memory.
void load_libs(ctx_t* ctx);

#endif
