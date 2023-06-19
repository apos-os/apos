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

#include "common/kassert.h"
#include "common/hashtable.h"
#include "test/ktest.h"

#define EXPECT_IN_TABLE(tbl, key, value) do { \
  void* _OUT; \
  KEXPECT_EQ(0, htbl_get(tbl, key, &_OUT)); \
  KEXPECT_EQ(value, (intptr_t)_OUT); \
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

  KTEST_BEGIN("cleanup test");
  // Add a bunch of nodes (twice per key) then don't remove them.
  for (intptr_t i = 0; i < 100; ++i) {
    htbl_put(tbl, i, (void*)i);
    htbl_put(tbl, i, (void*)i);
  }
}

#define ITERATE_SIZE 10
static int g_iterate_vals[10];
static void iterate_func(void* arg, uint32_t key, void* val) {
  int* counter = (int*)arg;
  KASSERT(key < ITERATE_SIZE);
  g_iterate_vals[key] = (intptr_t)val;
  (*counter)++;
}

void iterate_test(htbl_t* tbl) {
  KTEST_BEGIN("iterate test");

  for (int i = 0; i < ITERATE_SIZE; ++i) {
    g_iterate_vals[i] = 0;
  }
  int iterate_ctr = 0;

  htbl_put(tbl, 1, (void*)301);
  htbl_put(tbl, 3, (void*)303);
  htbl_put(tbl, 4, (void*)304);
  htbl_put(tbl, 6, (void*)306);

  htbl_iterate(tbl, &iterate_func, &iterate_ctr);
  KEXPECT_EQ(4, iterate_ctr);
  KEXPECT_EQ(0, g_iterate_vals[0]);
  KEXPECT_EQ(301, g_iterate_vals[1]);
  KEXPECT_EQ(0, g_iterate_vals[2]);
  KEXPECT_EQ(303, g_iterate_vals[3]);
  KEXPECT_EQ(304, g_iterate_vals[4]);
  KEXPECT_EQ(0, g_iterate_vals[5]);
  KEXPECT_EQ(306, g_iterate_vals[6]);
  KEXPECT_EQ(0, g_iterate_vals[7]);

  htbl_remove(tbl, 1);
  htbl_remove(tbl, 4);

  iterate_ctr = 0;
  htbl_iterate(tbl, &iterate_func, &iterate_ctr);
  KEXPECT_EQ(2, iterate_ctr);

  htbl_remove(tbl, 3);
  htbl_remove(tbl, 6);
}

static void clear_test(htbl_t* tbl) {
  KTEST_BEGIN("htbl_clear(): basic test");

  for (int i = 0; i < ITERATE_SIZE; ++i) {
    g_iterate_vals[i] = 0;
  }
  int iterate_ctr = 0;

  htbl_put(tbl, 1, (void*)301);
  htbl_put(tbl, 3, (void*)303);
  htbl_put(tbl, 4, (void*)304);
  htbl_put(tbl, 6, (void*)306);

  htbl_clear(tbl, &iterate_func, &iterate_ctr);
  KEXPECT_EQ(4, iterate_ctr);
  KEXPECT_EQ(0, g_iterate_vals[0]);
  KEXPECT_EQ(301, g_iterate_vals[1]);
  KEXPECT_EQ(0, g_iterate_vals[2]);
  KEXPECT_EQ(303, g_iterate_vals[3]);
  KEXPECT_EQ(304, g_iterate_vals[4]);
  KEXPECT_EQ(0, g_iterate_vals[5]);
  KEXPECT_EQ(306, g_iterate_vals[6]);
  KEXPECT_EQ(0, g_iterate_vals[7]);

  KEXPECT_EQ(0, htbl_size(tbl));
  void* val;
  KEXPECT_EQ(-1, htbl_get(tbl, 1, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 3, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 4, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 6, &val));
}

static bool filter_func(void* arg, uint32_t key, void* val) {
  int* counter = (int*)arg;
  KASSERT(*counter < ITERATE_SIZE);
  g_iterate_vals[*counter] = (intptr_t)val;
  (*counter)++;
  if (key % 3 == 0 || key % 7 == 0) {
    return false;
  } else {
    return true;
  }
}

static void filter_test(htbl_t* tbl) {
  KTEST_BEGIN("htbl_filter(): basic test");

  for (int i = 0; i < ITERATE_SIZE; ++i) {
    g_iterate_vals[i] = -1;
  }
  int iterate_ctr = 0;

  htbl_put(tbl, 1, (void*)301);
  htbl_put(tbl, 3, (void*)303);
  htbl_put(tbl, 4, (void*)304);
  htbl_put(tbl, 6, (void*)306);
  htbl_put(tbl, 14, (void*)314);
  htbl_put(tbl, 21, (void*)321);
  htbl_put(tbl, 19, (void*)319);
  htbl_put(tbl, 37, (void*)337);

  KEXPECT_EQ(4, htbl_filter(tbl, &filter_func, &iterate_ctr));
  KEXPECT_EQ(8, iterate_ctr);
  KEXPECT_EQ(-1, g_iterate_vals[8]);

  KEXPECT_EQ(4, htbl_size(tbl));
  void* val;
  KEXPECT_EQ(0, htbl_get(tbl, 1, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 3, &val));
  KEXPECT_EQ(0, htbl_get(tbl, 4, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 6, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 14, &val));
  KEXPECT_EQ(-1, htbl_get(tbl, 21, &val));
  KEXPECT_EQ(0, htbl_get(tbl, 19, &val));
  KEXPECT_EQ(0, htbl_get(tbl, 37, &val));

  htbl_remove(tbl, 1);
  htbl_remove(tbl, 4);
  htbl_remove(tbl, 19);
  htbl_remove(tbl, 37);
}

static void hashtable_size_test(void) {
  KTEST_BEGIN("hashtable: size");
  htbl_t tbl;
  void* val;
  htbl_init(&tbl, 4);

  KEXPECT_EQ(0, htbl_size(&tbl));

  htbl_put(&tbl, 1, (void*)0x1);
  EXPECT_IN_TABLE(&tbl, 1, 0x1);
  KEXPECT_EQ(1, htbl_size(&tbl));

  htbl_put(&tbl, 2, (void*)0x2);
  EXPECT_IN_TABLE(&tbl, 2, 0x2);
  KEXPECT_EQ(2, htbl_size(&tbl));

  htbl_put(&tbl, 2, (void*)0x3);
  EXPECT_IN_TABLE(&tbl, 2, 0x3);
  KEXPECT_EQ(2, htbl_size(&tbl));

  KEXPECT_EQ(0, htbl_remove(&tbl, 1));
  KEXPECT_NE(0, htbl_get(&tbl, 1, &val));
  KEXPECT_EQ(1, htbl_size(&tbl));

  KEXPECT_NE(0, htbl_remove(&tbl, 1));
  KEXPECT_EQ(1, htbl_size(&tbl));

  htbl_cleanup(&tbl);


  KTEST_BEGIN("hashtable: grows when full");
  htbl_init(&tbl, 1);

  htbl_put(&tbl, 2, (void*)0x1);
  KEXPECT_EQ(2, htbl_num_buckets(&tbl));
  htbl_put(&tbl, 10, (void*)0x2);
  KEXPECT_EQ(4, htbl_num_buckets(&tbl));
  htbl_put(&tbl, 18, (void*)0x3);
  KEXPECT_EQ(8, htbl_num_buckets(&tbl));
  htbl_put(&tbl, 26, (void*)0x4);
  KEXPECT_EQ(8, htbl_num_buckets(&tbl));
  htbl_put(&tbl, 34, (void*)0x5);
  KEXPECT_EQ(8, htbl_num_buckets(&tbl));

  EXPECT_IN_TABLE(&tbl, 2, 0x1);
  EXPECT_IN_TABLE(&tbl, 10, 0x2);
  EXPECT_IN_TABLE(&tbl, 18, 0x3);
  EXPECT_IN_TABLE(&tbl, 26, 0x4);
  EXPECT_IN_TABLE(&tbl, 34, 0x5);

  htbl_cleanup(&tbl);
}

static bool filter_even(void* arg, uint32_t key, void* val) {
  return key % 2 == 0;
}

static void hashtable_big_filter_test(void) {
  KTEST_BEGIN("hashtable: big filter test");
  htbl_t tbl;
  void* val;

  const int kNumVals = 1000;
  htbl_init(&tbl, kNumVals * 1.5);
  for (int i = 0; i < kNumVals; ++i) {
    htbl_put(&tbl, i, NULL);
  }

  // Force a resize down to create lots of collisions.
  htbl_resize(&tbl, kNumVals / 10);

  KEXPECT_EQ(kNumVals, htbl_size(&tbl));
  KEXPECT_EQ(kNumVals / 2, htbl_filter(&tbl, &filter_even, NULL));
  KEXPECT_EQ(kNumVals / 2, htbl_size(&tbl));

  for (int i = 0; i < kNumVals; ++i) {
    if (i % 2 == 0) {
      KEXPECT_EQ(0, htbl_get(&tbl, i, &val));
    } else {
      KEXPECT_EQ(-1, htbl_get(&tbl, i, &val));
    }
  }
  htbl_cleanup(&tbl);
}

void hashtable_test(void) {
  KTEST_SUITE_BEGIN("hashtable (large table)");
  htbl_t t;
  htbl_init(&t, 100);
  iterate_test(&t);
  clear_test(&t);
  filter_test(&t);
  do_table_test(&t);
  htbl_cleanup(&t);

  KTEST_SUITE_BEGIN("hashtable (small table)");
  // Guarantee some collisions.
  htbl_init(&t, 2);
  iterate_test(&t);
  clear_test(&t);
  filter_test(&t);
  do_table_test(&t);
  htbl_cleanup(&t);

  KTEST_SUITE_BEGIN("hashtable (general tests)");
  hashtable_size_test();
  hashtable_big_filter_test();
}
