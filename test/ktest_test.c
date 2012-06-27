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

#include "test/ktest.h"

void ktest_test() {
  KTEST_SUITE_BEGIN("ktest");

  KTEST_BEGIN("KEXPECT_EQ");
  KEXPECT_EQ(1, 1);
  KEXPECT_EQ(1, 2);

  KTEST_BEGIN("KEXPECT_STREQ");
  KEXPECT_STREQ("abc", "abc");
  KEXPECT_STREQ("abc", "def");

  KTEST_BEGIN("KEXPECT_NE");
  KEXPECT_NE(1, 2);
  KEXPECT_NE(1, 1);

  KTEST_BEGIN("KEXPECT_STRNE");
  KEXPECT_STRNE("abc", "def");
  KEXPECT_STRNE("abc", "abc");

  KTEST_BEGIN("KEXPECT_LT");
  KEXPECT_LT(1, 2);
  KEXPECT_LT(-1, 0);
  KEXPECT_LT(1, 1);
  KEXPECT_LT(2, 1);

  KTEST_BEGIN("KEXPECT_LE");
  KEXPECT_LE(1, 2);
  KEXPECT_LE(-1, 0);
  KEXPECT_LE(1, 1);
  KEXPECT_LE(2, 1);

  KTEST_BEGIN("KEXPECT_GT");
  KEXPECT_GT(3, 2);
  KEXPECT_GT(0, -1);
  KEXPECT_GT(1, 1);
  KEXPECT_GT(0, 1);

  KTEST_BEGIN("KEXPECT_GE");
  KEXPECT_GE(3, 2);
  KEXPECT_GE(0, -1);
  KEXPECT_GE(1, 1);
  KEXPECT_GE(0, 1);
}
