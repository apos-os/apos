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
#include "os/core/loader/gnu_hash.h"

#include "proc/load/elf-internal.h"

#ifdef APOS_NATIVE_TARGET
# include <assert.h>
# include <stdio.h>
# include <string.h>
# define KASSERT(x) assert(x)
# define ld_printf printf
# define kmemset memset
# define kstrcmp strcmp
#else
# include "os/core/loader/ld_assert.h"
# include "os/core/loader/ld_printf.h"
# include "os/core/loader/ld_string.h"
#endif

static const uint64_t* get_bloom_filter(const gnu_hash_header_t* hdr) {
  size_t offset = sizeof(gnu_hash_header_t) / 8;
  return (const uint64_t*)hdr + offset;
}

static const uint32_t* get_hash_buckets(const gnu_hash_header_t* hdr) {
  size_t offset = sizeof(gnu_hash_header_t) / 4 + hdr->maskwords * 2;
  return (const uint32_t*)hdr + offset;
}

static const uint32_t* get_hash_values(const gnu_hash_header_t* hdr) {
  size_t offset =
      sizeof(gnu_hash_header_t) / 4 + hdr->maskwords * 2 + hdr->nbuckets;
  return (const uint32_t*)hdr + offset;
}

uint32_t gnu_hash(const char* s) {
  uint32_t hash = 5381;
  while (*s) {
    hash = (hash * 33) + *s;
    s++;
  }
  return hash;
}

const Elf64_Sym* gnu_hash_lookup(const elf64_dyninfo_t* dyn,
                                 const char* symbol, uint32_t sym_hash) {
  // First check the bloom filter.
  const gnu_hash_header_t* hdr = dyn->gnu_hash;

  uint32_t sym_hash2 = sym_hash >> hdr->shift2;
  const size_t kBitsPerMaskWord = 8 * sizeof(uint64_t);
  size_t maskword = (sym_hash / kBitsPerMaskWord) % hdr->maskwords;
  uint64_t bloommask = (1ULL << (sym_hash % kBitsPerMaskWord)) |
                       (1ULL << (sym_hash2 % kBitsPerMaskWord));
  if ((get_bloom_filter(hdr)[maskword] & bloommask) != bloommask) {
    return NULL;
  }

  // Find the hash bucket for the symbol, then search the chain for a match.
  const uint32_t bucket = sym_hash % hdr->nbuckets;
  uint32_t symidx = get_hash_buckets(hdr)[bucket];
  if (symidx == 0) {
    return NULL;  // Nothing in this bucket.
  }
  const uint32_t* chain = &get_hash_values(hdr)[symidx - hdr->symndx];
  while (1) {
    if ((*chain & ~1) == (sym_hash & ~1)) {
      // Hash match!  Let's check strings.
      const Elf64_Sym* sym = &dyn->symtab[symidx];
      const char* entry_name = dyn->strtab + sym->st_name;
      if (kstrcmp(entry_name, symbol) == 0) {
        return sym;
      }
    }
    if (*chain & 1) {
      break;
    }
    chain++;
    symidx++;
  }
  return NULL;
}
