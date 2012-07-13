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

#include "common/hashtable.h"
#include "test/ktest.h"

#define EXPECT_IN_TABLE(tbl, key, value) do { \
  void* _OUT; \
  KEXPECT_EQ(0, htbl_get(tbl, key, &_OUT)); \
  KEXPECT_EQ(value, (uint32_t)_OUT); \
} while(0);

static void do_table_test(htbl_t* tbl) {
  void* out;
  KTEST_BEGIN("empty get test");
  KEXPECT_NE(0, htbl_get(tbl, 1, &out));

  KTEST_BEGIN("put test");
  htbl_put(tbl, 1, (void*)100);
  EXPECT_IN_TABLE(tbl, 1, 100);

  KTEST_BEGIN("remove test");
  KEXPECT_EQ(0, htbl_remove(tbl, 1));
  KEXPECT_NE(0, htbl_get(tbl, 1, &out));

  KTEST_BEGIN("double remove");
  KEXPECT_NE(0, htbl_remove(tbl, 1));

  KTEST_BEGIN("multi test");
  htbl_put(tbl, 1, (void*)101);
  htbl_put(tbl, 2, (void*)102);
  htbl_put(tbl, 3, (void*)103);
  htbl_put(tbl, 4, (void*)104);

  EXPECT_IN_TABLE(tbl, 1, 101);
  EXPECT_IN_TABLE(tbl, 2, 102);
  EXPECT_IN_TABLE(tbl, 3, 103);
  EXPECT_IN_TABLE(tbl, 4, 104);

  htbl_put(tbl, 3, (void*)303);
  EXPECT_IN_TABLE(tbl, 1, 101);
  EXPECT_IN_TABLE(tbl, 2, 102);
  EXPECT_IN_TABLE(tbl, 3, 303);
  EXPECT_IN_TABLE(tbl, 4, 104);

  htbl_put(tbl, 2, (void*)402);
  htbl_put(tbl, 3, (void*)403);
  EXPECT_IN_TABLE(tbl, 1, 101);
  EXPECT_IN_TABLE(tbl, 2, 402);
  EXPECT_IN_TABLE(tbl, 3, 403);
  EXPECT_IN_TABLE(tbl, 4, 104);

  KEXPECT_EQ(0, htbl_remove(tbl, 3));
  EXPECT_IN_TABLE(tbl, 1, 101);
  EXPECT_IN_TABLE(tbl, 2, 402);
  KEXPECT_NE(0, htbl_get(tbl, 3, &out));
  EXPECT_IN_TABLE(tbl, 4, 104);

  KEXPECT_EQ(0, htbl_remove(tbl, 1));
  KEXPECT_EQ(0, htbl_remove(tbl, 2));
  KEXPECT_NE(0, htbl_remove(tbl, 3));
  KEXPECT_EQ(0, htbl_remove(tbl, 4));

  KEXPECT_NE(0, htbl_get(tbl, 1, &out));
  KEXPECT_NE(0, htbl_get(tbl, 2, &out));
  KEXPECT_NE(0, htbl_get(tbl, 3, &out));
  KEXPECT_NE(0, htbl_get(tbl, 4, &out));
}

void hashtable_test() {
  KTEST_SUITE_BEGIN("hashtable (large table)");
  htbl_t t;
  htbl_init(&t, 100);
  do_table_test(&t);
  htbl_cleanup(&t);

  KTEST_SUITE_BEGIN("hashtable (small table)");
  // Guarantee some collisions.
  htbl_init(&t, 2);
  do_table_test(&t);
  htbl_cleanup(&t);
}
