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
}

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"

#include <cstdint>

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
