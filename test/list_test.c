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

#include <stdint.h>

#include "common/list.h"
#include "test/ktest.h"

static int pop_all(list_t* list) {
  int count = 0;
  list_link_t* link = list_pop(list);
  while (link) {
    count++;
    link = list_pop(list);
  }
  return count;
}

static void basic_list_test() {
  const int kNumLinks = 10;
  list_t list = LIST_INIT;
  list_link_t links[kNumLinks];
  for (int i = 0; i < kNumLinks; ++i) links[i] = LIST_LINK_INIT;

  KTEST_BEGIN("empty list test");
  KEXPECT_NE(0, list_empty(&list));
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));

  KTEST_BEGIN("list_push()/list_pop() test");

  list_push(&list, &links[0]);

  KEXPECT_EQ(0, list_empty(&list));
  KEXPECT_EQ(&links[0], list_pop(&list));
  KEXPECT_NE(0, list_empty(&list));

  KTEST_BEGIN("list multi-push");
  for (int i = 0; i < kNumLinks; ++i) {
    list_push(&list, &links[i]);
    KEXPECT_NE(0, list_link_on_list(&list, &links[i]));
  }

  for (int i = 0; i < kNumLinks; ++i) {
    KEXPECT_NE(0, list_link_on_list(&list, &links[i]));
    KEXPECT_EQ(&links[i], list_pop(&list));
    KEXPECT_EQ(0, list_link_on_list(&list, &links[i]));
  }
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));

  KTEST_BEGIN("push/push/pop/push");
  list_push(&list, &links[0]);
  list_push(&list, &links[1]);
  KEXPECT_EQ(&links[0], list_pop(&list));
  list_push(&list, &links[2]);
  KEXPECT_EQ(&links[1], list_pop(&list));
  KEXPECT_EQ(&links[2], list_pop(&list));
}

static void list_remove_test() {
  const int kNumLinks = 5;
  list_t list = LIST_INIT;
  list_link_t links[kNumLinks];
  for (int i = 0; i < kNumLinks; ++i) links[i] = LIST_LINK_INIT;

  KTEST_BEGIN("list_remove() in middle test");
  for (int i = 0; i < kNumLinks; ++i) list_push(&list, &links[i]);

  const int kIdxToRemove = 2;
  list_remove(&list, &links[kIdxToRemove]);
  KEXPECT_EQ(0, list_link_on_list(&list, &links[kIdxToRemove]));
  for (int i = 0; i < kNumLinks; ++i) {
    if (i == kIdxToRemove) continue;
    KEXPECT_EQ(&links[i], list_pop(&list));
    KEXPECT_EQ(0, list_link_on_list(&list, &links[i]));
  }
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));

  KTEST_BEGIN("list_remove() first element");
  for (int i = 0; i < kNumLinks; ++i) list_push(&list, &links[i]);
  list_remove(&list, &links[0]);
  KEXPECT_EQ(0, list_link_on_list(&list, &links[0]));
  KEXPECT_EQ(&links[1], list_pop(&list));
  KEXPECT_EQ(kNumLinks - 2, pop_all(&list));

  KTEST_BEGIN("list_remove() last element");
  for (int i = 0; i < kNumLinks; ++i) list_push(&list, &links[i]);
  list_remove(&list, &links[kNumLinks - 1]);
  KEXPECT_EQ(0, list_link_on_list(&list, &links[kNumLinks - 1]));
  KEXPECT_EQ(&links[0], list_pop(&list));
  KEXPECT_EQ(kNumLinks - 2, pop_all(&list));

  KTEST_BEGIN("list_remove() only element");
  list_push(&list, &links[0]);
  list_remove(&list, &links[0]);
  KEXPECT_NE(0, list_empty(&list));
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));
  KEXPECT_EQ(0, list_link_on_list(&list, &links[0]));
}

void list_test() {
  KTEST_SUITE_BEGIN("list test");

  basic_list_test();
  list_remove_test();
}
