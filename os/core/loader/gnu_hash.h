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
//
// GNU symbol hash table implementation.
// Reference:
//   https://www.linker-aliens.org/blogs/ali/entry/gnu_hash_elf_sections/

#ifndef APOO_OS_CORE_LOADER_GNU_HASH_H
#define APOO_OS_CORE_LOADER_GNU_HASH_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "os/core/loader/elf64.h"
#include "proc/load/elf-internal.h"

// Section header.
typedef struct {
  uint32_t nbuckets;
  uint32_t symndx;
  uint32_t maskwords;
  uint32_t shift2;
} gnu_hash_header_t;
static_assert(sizeof(gnu_hash_header_t) == 4 * sizeof(uint32_t),
              "Bad gnu_hash_header_t size");

// Calculate the GNU hash for a symbol name.
uint32_t gnu_hash(const char* s);

// Look up a symbol in the given .gnu.hash section.  Returns the Elf*_Sym
// corresponding to the symbol, or NULL if it is not found.
const Elf64_Sym* gnu_hash_lookup(const elf64_dyninfo_t* dyn, const char* symbol,
                                 uint32_t sym_hash);

#endif
