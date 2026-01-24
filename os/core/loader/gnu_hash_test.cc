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

extern "C" {
#include "os/core/loader/elf64.h"
#include "os/core/loader/gnu_hash.h"
#include "os/core/loader/testdata/gnu_hash_lib.so.cdata"
#include "proc/load/elf-internal.h"
}

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"

#include <cstdint>

namespace {

const std::span<const unsigned char> kGnuHashLib{
    kGnuHashLibRaw, kGnuHashLibRaw + kGnuHashLibRaw_len};

static const std::pair<const char*, uint64_t> kSymbols[] = {
    {"abeyancies", 0x0000000000000a6c},     //
    {"dram", 0x00000000000009ca},           //
    {"abele", 0x0000000000000ab4},          //
    {"radioscopical", 0x0000000000000904},  //
    {"mordancy", 0x00000000000008f2},       //
    {"aasvogel", 0x000000000000093a},       //
    {"aahs", 0x0000000000000916},           //
    {"aaronic", 0x0000000000000928},        //
    {"abeyance", 0x0000000000000a36},       //
    {"_end", 0x0000000000001ce8},           //
    {"abedge", 0x0000000000000a00},         //
    {"abelian", 0x0000000000000aea},        //
    {"abeyancy", 0x0000000000000a5a},       //
    {"func3", 0x000000000000094c},          //
    {"abelia", 0x0000000000000ad8},         //
    {"abegge", 0x0000000000000a12},         //
    {"abed", 0x00000000000009dc},           //
    {"abede", 0x00000000000009ee},          //
    {"abeles", 0x0000000000000ac6},         //
    {"abeyant", 0x0000000000000a7e},        //
    {"abelite", 0x0000000000000b0e},        //
    {"abey", 0x0000000000000a24},           //
    {"abeigh", 0x0000000000000a90},         //
    {"abeyances", 0x0000000000000a48},      //
    {"aals", 0x0000000000000994},           //
    {"gliosa", 0x0000000000000982},         //
    {"aam", 0x00000000000009a6},            //
    {"abelicea", 0x0000000000000afc},       //
    {"colloquizing", 0x0000000000000970},   //
    {"aarrghh", 0x00000000000009b8},        //
    {"monologuist", 0x000000000000095e},    //
    {"abel", 0x0000000000000aa2},           //
};

TEST(GnuHash, BasicHashes) {
  EXPECT_EQ(5381, gnu_hash(""));
  EXPECT_EQ(0x0002b606, gnu_hash("a"));
  EXPECT_EQ(0x00597728, gnu_hash("ab"));
  EXPECT_EQ(0x6ccde37d, gnu_hash("abeyance"));
  EXPECT_EQ(0x068a5390, gnu_hash("abeyances"));
  EXPECT_EQ(0x6ccde391, gnu_hash("abeyancy"));
  EXPECT_EQ(0xd7d4d539, gnu_hash("abeyancies"));
  EXPECT_EQ(0x1a91e029, gnu_hash("abeyant"));
  EXPECT_EQ(0xf149f9c5, gnu_hash("abeigh"));
  EXPECT_EQ(0x7c93ee99, gnu_hash("abel"));
  EXPECT_EQ(0x0f11c21e, gnu_hash("abele"));
  EXPECT_EQ(0xf14a0651, gnu_hash("abeles"));
  EXPECT_EQ(0xf14a06c3, gnu_hash("abelia"));
  EXPECT_EQ(0x1a8adf91, gnu_hash("abelian"));
  EXPECT_EQ(0x6be6d96b, gnu_hash("abelicea"));
  EXPECT_EQ(0x1a8ae1fb, gnu_hash("abelite"));
}

elf64_dyninfo_t GetDynInfo(std::span<const unsigned char> data) {
  elf64_dyninfo_t out;

  const unsigned char* elf = data.data();
  const Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf;
  EXPECT_LT(ehdr->e_phoff, data.size());
  EXPECT_LT(ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize, data.size());
  EXPECT_EQ(ehdr->e_phentsize, sizeof(Elf64_Phdr));

  const Elf64_Phdr* phdrs = (const Elf64_Phdr*)(elf + ehdr->e_phoff);
  const Elf64_Phdr* dyn_phdr = NULL;
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    if (phdrs[i].p_type == PT_DYNAMIC) {
      dyn_phdr = &phdrs[i];
      break;
    }
  }
  EXPECT_NE(dyn_phdr, nullptr);

  // Find the appropriate dynamic sections.
  const Elf64_Dyn* dyns = (const Elf64_Dyn*)(elf + dyn_phdr->p_offset);
  EXPECT_EQ(dyn_phdr->p_filesz % sizeof(Elf64_Dyn), 0);
  for (size_t i = 0; i < dyn_phdr->p_filesz / sizeof(Elf64_Dyn); ++i) {
    const Elf64_Dyn* dyn = &dyns[i];
    switch (dyn->d_tag) {
      case DT_SYMTAB:
        out.symtab = (const Elf64_Sym*)(elf + dyn->d_un.d_ptr);
        break;

      case DT_SYMENT:
        EXPECT_EQ(dyn->d_un.d_val, sizeof(Elf64_Sym));
        break;

      case DT_STRTAB:
        out.strtab = (const char*)(elf + dyn->d_un.d_ptr);
        break;

      case DT_GNU_HASH:
        out.gnu_hash = elf + dyn->d_un.d_ptr;
        break;
    }
  }

  return out;
}

TEST(GnuHash, ParseTestdata) {
  elf64_dyninfo_t dyn = GetDynInfo(kGnuHashLib);
  EXPECT_EQ(0x158, (unsigned char*)dyn.gnu_hash - kGnuHashLib.data());
  EXPECT_EQ(0x5f8, (unsigned char*)dyn.strtab - kGnuHashLib.data());
  EXPECT_EQ(0x250, (unsigned char*)dyn.symtab - kGnuHashLib.data());
}

const Elf64_Sym* DoLookup(const elf64_dyninfo_t* d, const char* symbol) {
  return gnu_hash_lookup(d, symbol, gnu_hash(symbol));
}

TEST(GnuHash, BasicLookup) {
  elf64_dyninfo_t s = GetDynInfo(kGnuHashLib);

  for (int i = 0; i < sizeof(kSymbols) / sizeof(kSymbols[0]); ++i) {
    SCOPED_TRACE(kSymbols[i].first);
    const Elf64_Sym* sym = DoLookup(&s, kSymbols[i].first);
    EXPECT_NE(nullptr, sym);
    if (sym) {
      EXPECT_STREQ(kSymbols[i].first, s.strtab + sym->st_name);
      EXPECT_EQ(kSymbols[i].second, sym->st_value);
    }
  }

  // These symbols should not be found in the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "abcd"));
  EXPECT_EQ(nullptr, DoLookup(&s, "func1"));
  EXPECT_EQ(nullptr, DoLookup(&s, "_long_symbol_name"));
  EXPECT_EQ(nullptr, DoLookup(&s, ""));

  // This has a hash collision with an entry in the table but isn't itself in
  // the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "vivency"));
}

TEST(GnuHash, BloomFilterFull) {
  std::vector<unsigned char> lib_mod(std::begin(kGnuHashLib),
                                     std::end(kGnuHashLib));

  elf64_dyninfo_t s = GetDynInfo(lib_mod);

  // Override the bloom filter to be all ones.  This should not affect the
  // lookups semantically.
  uint32_t* data = (uint32_t*)s.gnu_hash;
  const gnu_hash_header_t* hdr = (const gnu_hash_header_t*)s.gnu_hash;
  for (int i = 0; i < hdr->maskwords * 2; ++i) {
    data[sizeof(gnu_hash_header_t) / sizeof(uint32_t) + i] = 0xffffffff;
  }

  for (int i = 0; i < sizeof(kSymbols) / sizeof(kSymbols[0]); ++i) {
    SCOPED_TRACE(kSymbols[i].first);
    const Elf64_Sym* sym = DoLookup(&s, kSymbols[i].first);
    EXPECT_NE(nullptr, sym);
    if (sym) {
      EXPECT_STREQ(kSymbols[i].first, s.strtab + sym->st_name);
      EXPECT_EQ(kSymbols[i].second, sym->st_value);
    }
  }

  // These symbols should not be found in the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "abcd"));
  EXPECT_EQ(nullptr, DoLookup(&s, "func1"));
  EXPECT_EQ(nullptr, DoLookup(&s, "_long_symbol_name"));
  EXPECT_EQ(nullptr, DoLookup(&s, ""));

  // This has a hash collision with an entry in the table but isn't itself in
  // the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "vivency"));
}

TEST(GnuHash, BloomFilterEmpty) {
  std::vector<unsigned char> lib_mod(std::begin(kGnuHashLib),
                                     std::end(kGnuHashLib));

  elf64_dyninfo_t s = GetDynInfo(lib_mod);

  // Override the bloom filter to be all zeroes.  All lookups should fail now.
  uint32_t* data = (uint32_t*)s.gnu_hash;
  const gnu_hash_header_t* hdr = (const gnu_hash_header_t*)s.gnu_hash;
  for (int i = 0; i < hdr->maskwords * 2; ++i) {
    data[sizeof(gnu_hash_header_t) / sizeof(uint32_t) + i] = 0;
  }

  for (int i = 0; i < sizeof(kSymbols) / sizeof(kSymbols[0]); ++i) {
    SCOPED_TRACE(kSymbols[i].first);
    const Elf64_Sym* sym = DoLookup(&s, kSymbols[i].first);
    EXPECT_EQ(nullptr, sym);
  }

  // These symbols should not be found in the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "abcd"));
  EXPECT_EQ(nullptr, DoLookup(&s, "func1"));
  EXPECT_EQ(nullptr, DoLookup(&s, "_long_symbol_name"));
  EXPECT_EQ(nullptr, DoLookup(&s, ""));

  // This has a hash collision with an entry in the table but isn't itself in
  // the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "vivency"));
}

TEST(GnuHash, BloomFilterPartial) {
  std::vector<unsigned char> lib_mod(std::begin(kGnuHashLib),
                                     std::end(kGnuHashLib));

  elf64_dyninfo_t s = GetDynInfo(lib_mod);

  // Zero out the bloom filter, then set the bits just for one symbol (but which
  // shares its bits with other symbols)
  uint64_t* mask =
      (uint64_t*)((uintptr_t)s.gnu_hash + sizeof(gnu_hash_header_t));
  const gnu_hash_header_t* hdr = (const gnu_hash_header_t*)s.gnu_hash;
  for (int i = 0; i < hdr->maskwords; ++i) {
    mask[i] = 0;
  }
  mask[2] = 0x0000400000020000;

  // Nothing except 'abed' should succeed lookup.  "abey" and "abel" share
  // bits with "abed".
  for (int i = 0; i < sizeof(kSymbols) / sizeof(kSymbols[0]); ++i) {
    if (strcmp(kSymbols[i].first, "abed") == 0) continue;
    SCOPED_TRACE(kSymbols[i].first);
    const Elf64_Sym* sym = DoLookup(&s, kSymbols[i].first);
    EXPECT_EQ(nullptr, sym);
  }

  // These symbols should not be found in the table.
  EXPECT_EQ(nullptr, DoLookup(&s, "abcd"));
  EXPECT_EQ(nullptr, DoLookup(&s, "func1"));
  EXPECT_EQ(nullptr, DoLookup(&s, "_long_symbol_name"));
  EXPECT_EQ(nullptr, DoLookup(&s, ""));
  EXPECT_EQ(nullptr, DoLookup(&s, "vivency"));

  // "abed" lookup should suceeed.
  const Elf64_Sym* sym = DoLookup(&s, "abed");
  ASSERT_NE(nullptr, sym);
  EXPECT_STREQ("abed", s.strtab + sym->st_name);
}

}
