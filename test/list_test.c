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

static void push_all(list_t* list, list_link_t links[], int num) {
  for (int i = 0; i < num; ++i) {
    list_push(list, &links[i]);
  }
}

static void basic_list_test(void) {
  const int kNumLinks = 10;
  list_t list = LIST_INIT;
  list_link_t links[kNumLinks];
  for (int i = 0; i < kNumLinks; ++i) links[i] = LIST_LINK_INIT;

  KTEST_BEGIN("empty list test");
  KEXPECT_NE(0, list_empty(&list));
  KEXPECT_EQ(0, list_size(&list));
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));

  KTEST_BEGIN("list_push()/list_pop() test");

  list_push(&list, &links[0]);
  KEXPECT_EQ(1, list_size(&list));

  KEXPECT_EQ(0, list_empty(&list));
  KEXPECT_EQ(&links[0], list_pop(&list));
  KEXPECT_NE(0, list_empty(&list));
  KEXPECT_EQ(0, list_size(&list));

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

static void list_remove_test(void) {
  const int kNumLinks = 5;
  list_t list = LIST_INIT;
  list_link_t links[kNumLinks];
  for (int i = 0; i < kNumLinks; ++i) links[i] = LIST_LINK_INIT;

  KTEST_BEGIN("list_remove() in middle test");
  for (int i = 0; i < kNumLinks; ++i) list_push(&list, &links[i]);

  const int kIdxToRemove = 2;
  KEXPECT_EQ(&links[kIdxToRemove + 1],
             list_remove(&list, &links[kIdxToRemove]));
  KEXPECT_EQ(0, list_link_on_list(&list, &links[kIdxToRemove]));
  for (int i = 0; i < kNumLinks; ++i) {
    if (i == kIdxToRemove) continue;
    KEXPECT_EQ(&links[i], list_pop(&list));
    KEXPECT_EQ(0, list_link_on_list(&list, &links[i]));
  }
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));

  KTEST_BEGIN("list_remove() first element");
  for (int i = 0; i < kNumLinks; ++i) list_push(&list, &links[i]);
  KEXPECT_EQ(&links[1], list_remove(&list, &links[0]));
  KEXPECT_EQ(0, list_link_on_list(&list, &links[0]));
  KEXPECT_EQ(&links[1], list_pop(&list));
  KEXPECT_EQ(kNumLinks - 2, pop_all(&list));

  KTEST_BEGIN("list_remove() last element");
  for (int i = 0; i < kNumLinks; ++i) list_push(&list, &links[i]);
  KEXPECT_EQ(NULL, list_remove(&list, &links[kNumLinks - 1]));
  KEXPECT_EQ(0, list_link_on_list(&list, &links[kNumLinks - 1]));
  KEXPECT_EQ(&links[0], list_pop(&list));
  KEXPECT_EQ(kNumLinks - 2, pop_all(&list));

  KTEST_BEGIN("list_remove() only element");
  list_push(&list, &links[0]);
  KEXPECT_EQ(NULL, list_remove(&list, &links[0]));
  KEXPECT_NE(0, list_empty(&list));
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));
  KEXPECT_EQ(0, list_link_on_list(&list, &links[0]));
}

static void list_insert_test(void) {
  const int kNumLinks = 5;
  list_t list = LIST_INIT;
  list_link_t links[kNumLinks];
  list_link_t new_link = LIST_LINK_INIT;
  for (int i = 0; i < kNumLinks; ++i) links[i] = LIST_LINK_INIT;

  KTEST_BEGIN("list: insert at beginning test");
  push_all(&list, links, kNumLinks);
  list_insert(&list, 0x0, &new_link);
  KEXPECT_EQ(kNumLinks + 1, list_size(&list));
  KEXPECT_EQ(&new_link, list_pop(&list));
  KEXPECT_EQ(&links[0], list_pop(&list));

  pop_all(&list);

  KTEST_BEGIN("list: insert at end test");
  push_all(&list, links, kNumLinks);
  list_insert(&list, &links[kNumLinks - 1], &new_link);
  KEXPECT_EQ(kNumLinks + 1, list_size(&list));
  for (int i = 0; i < kNumLinks; ++i) {
    KEXPECT_EQ(&links[i], list_pop(&list));
  }
  KEXPECT_EQ(&new_link, list_pop(&list));
  KEXPECT_NE(0, list_empty(&list));

  KTEST_BEGIN("list: insert in middle test");
  push_all(&list, links, kNumLinks);
  list_insert(&list, &links[2], &new_link);
  KEXPECT_EQ(kNumLinks + 1, list_size(&list));
  KEXPECT_EQ(&links[0], list_pop(&list));
  KEXPECT_EQ(&links[1], list_pop(&list));
  KEXPECT_EQ(&links[2], list_pop(&list));
  KEXPECT_EQ(&new_link, list_pop(&list));
  KEXPECT_EQ(&links[3], list_pop(&list));
  pop_all(&list);

  KTEST_BEGIN("list: insert on empty list");
  KEXPECT_NE(0, list_empty(&list));
  list_insert(&list, 0x0, &new_link);
  KEXPECT_EQ(0, list_empty(&list));
  KEXPECT_EQ(1, list_size(&list));
  KEXPECT_EQ(&new_link, list.head);
  KEXPECT_EQ(&new_link, list.tail);
  KEXPECT_EQ((list_link_t*)0x0, new_link.prev);
  KEXPECT_EQ((list_link_t*)0x0, new_link.next);
  KEXPECT_EQ(&new_link, list_pop(&list));
  KEXPECT_EQ((list_link_t*)0x0, list_pop(&list));
  KEXPECT_NE(0, list_empty(&list));
}

struct test_datum {
  int x;
  list_link_t td_link;
};
typedef struct test_datum test_datum_t;

static void list_iterate_test(void) {
  KTEST_BEGIN("Basic list iteration");
  test_datum_t nodes[4];
  int result[4] = {0, 0, 0, 0};
  list_t list = LIST_INIT;
  for (int i =0; i < 4; ++i) {
    nodes[i].x = (i + 1) * 10;
    nodes[i].td_link = LIST_LINK_INIT;
    list_push(&list, &nodes[i].td_link);
  }

  int i = 0;
  FOR_EACH_LIST(td_iter, &list) {
    test_datum_t* td = LIST_ENTRY(td_iter, test_datum_t, td_link);
    result[i++] = td->x;
  }
  KEXPECT_EQ(10, result[0]);
  KEXPECT_EQ(20, result[1]);
  KEXPECT_EQ(30, result[2]);
  KEXPECT_EQ(40, result[3]);

  KTEST_BEGIN("Basic const value, non-const list iteration");
  i = 0;
  FOR_EACH_LIST(td_iter, &list) {
    const test_datum_t* td = LIST_ENTRY(td_iter, test_datum_t, td_link);
    result[i++] = td->x;
  }
  KEXPECT_EQ(10, result[0]);
  KEXPECT_EQ(20, result[1]);
  KEXPECT_EQ(30, result[2]);
  KEXPECT_EQ(40, result[3]);
  KTEST_BEGIN("Basic const list iteration");
  const list_t* const_list = &list;
  i = 0;
  FOR_EACH_LIST(td_iter, const_list) {
    const test_datum_t* td = LIST_ENTRY(td_iter, test_datum_t, td_link);
    result[i++] = td->x;
  }
  KEXPECT_EQ(10, result[0]);
  KEXPECT_EQ(20, result[1]);
  KEXPECT_EQ(30, result[2]);
  KEXPECT_EQ(40, result[3]);

  KTEST_BEGIN("List iteration expression evaluates once");
  int list_idx = 0;
  const list_t* list_array[2] = {&list, NULL};
  i = 0;
  FOR_EACH_LIST(td_iter, list_array[list_idx++]) {
    test_datum_t* td = LIST_ENTRY(td_iter, test_datum_t, td_link);
    result[i++] = td->x * 10;
  }
  KEXPECT_EQ(1, list_idx);
  KEXPECT_EQ(100, result[0]);
  KEXPECT_EQ(200, result[1]);
  KEXPECT_EQ(300, result[2]);
  KEXPECT_EQ(400, result[3]);
}

void list_test(void) {
  KTEST_SUITE_BEGIN("list test");

  basic_list_test();
  list_remove_test();
  list_insert_test();
  list_iterate_test();
}
