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
#include "os/core/loader/gnu_hash.h"
#include "os/core/loader/testdata/gnu_hash_lib.so.cdata"
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
    {"abeyancies", 0x0000000000000a64},     //
    {"dram", 0x00000000000009c2},           //
    {"abele", 0x0000000000000aac},          //
    {"radioscopical", 0x00000000000008fc},  //
    {"mordancy", 0x00000000000008ea},       //
    {"aasvogel", 0x0000000000000932},       //
    {"aahs", 0x000000000000090e},           //
    {"aaronic", 0x0000000000000920},        //
    {"abeyance", 0x0000000000000a2e},       //
    {"_end", 0x0000000000001ce0},           //
    {"abedge", 0x00000000000009f8},         //
    {"abelian", 0x0000000000000ae2},        //
    {"abeyancy", 0x0000000000000a52},       //
    {"func3", 0x0000000000000944},          //
    {"abelia", 0x0000000000000ad0},         //
    {"abegge", 0x0000000000000a0a},         //
    {"abed", 0x00000000000009d4},           //
    {"abede", 0x00000000000009e6},          //
    {"abeles", 0x0000000000000abe},         //
    {"abeyant", 0x0000000000000a76},        //
    {"abelite", 0x0000000000000b06},        //
    {"abey", 0x0000000000000a1c},           //
    {"abeigh", 0x0000000000000a88},         //
    {"abeyances", 0x0000000000000a40},      //
    {"aals", 0x000000000000098c},           //
    {"gliosa", 0x000000000000097a},         //
    {"aam", 0x000000000000099e},            //
    {"abelicea", 0x0000000000000af4},       //
    {"colloquizing", 0x0000000000000968},   //
    {"aarrghh", 0x00000000000009b0},        //
    {"monologuist", 0x0000000000000956},    //
    {"abel", 0x0000000000000a9a},           //
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

TEST(GnuHash, ParseTestdata) {
  gnu_hash_section_t s;
  EXPECT_EQ(0, gnu_hash_get_section(kGnuHashLib.data(),
                                    kGnuHashLib.size_bytes(), &s));
  EXPECT_EQ(0x158, (unsigned char*)s.gnu_hash - kGnuHashLib.data());
  EXPECT_EQ(0x5f8, (unsigned char*)s.strtab - kGnuHashLib.data());
  EXPECT_EQ(0x250, (unsigned char*)s.symtab - kGnuHashLib.data());
  EXPECT_EQ(368, s.strsz);
}

const Elf64_Sym* DoLookup(const gnu_hash_section_t* s, const char* symbol) {
  return gnu_hash_lookup(s, symbol, gnu_hash(symbol));
}

TEST(GnuHash, BasicLookup) {
  gnu_hash_section_t s;
  EXPECT_EQ(0, gnu_hash_get_section(kGnuHashLib.data(),
                                    kGnuHashLib.size_bytes(), &s));

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

  gnu_hash_section_t s;
  EXPECT_EQ(0, gnu_hash_get_section(lib_mod.data(), lib_mod.size(), &s));

  // Override the bloom filter to be all ones.  This should not affect the
  // lookups semantically.
  uint32_t* data = (uint32_t*)s.gnu_hash;
  for (int i = 0; i < s.gnu_hash->maskwords * 2; ++i) {
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

  gnu_hash_section_t s;
  EXPECT_EQ(0, gnu_hash_get_section(lib_mod.data(), lib_mod.size(), &s));

  // Override the bloom filter to be all zeroes.  All lookups should fail now.
  uint32_t* data = (uint32_t*)s.gnu_hash;
  for (int i = 0; i < s.gnu_hash->maskwords * 2; ++i) {
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

  gnu_hash_section_t s;
  EXPECT_EQ(0, gnu_hash_get_section(lib_mod.data(), lib_mod.size(), &s));

  // Zero out the bloom filter, then set the bits just for one symbol (but which
  // shares its bits with other symbols)
  uint64_t* mask =
      (uint64_t*)((uintptr_t)s.gnu_hash + sizeof(gnu_hash_header_t));
  for (int i = 0; i < s.gnu_hash->maskwords; ++i) {
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
