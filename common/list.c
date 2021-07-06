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
#include "common/list.h"

#define SLOW_CONSISTENCY_CHECKS 0

const list_link_t LIST_LINK_INIT = { 0x0, 0x0 };
const list_t LIST_INIT = { 0x0, 0x0 };

void list_push(list_t* list, list_link_t* link) {
  KASSERT_DBG(link->prev == 0x0);
  KASSERT_DBG(link->next == 0x0);
  if (list->head == 0x0) {
    KASSERT_DBG(list->tail == 0x0);
    list->head = list->tail = link;
  } else {
    KASSERT_DBG(list->tail != 0x0);
    link->prev = list->tail;
    list->tail->next = link;
    list->tail = link;
  }
}

list_link_t* list_pop(list_t* list) {
  if (list->head == 0x0) {
    KASSERT_DBG(list->tail == 0x0);
    return 0x0;
  } else {
    list_link_t* link = list->head;
    KASSERT_DBG(link->prev == 0x0);
    if (link->next != 0x0) {
      KASSERT_DBG(list->tail != link);
      link->next->prev = 0x0;
      list->head = link->next;
      link->next = 0x0;
    } else {
      KASSERT_DBG(list->tail == list->head);
      list->tail = list->head = 0x0;
    }
    return link;
  }
}

void list_insert(list_t* list, list_link_t* prev, list_link_t* link) {
  KASSERT_DBG(link->prev == 0x0);
  KASSERT_DBG(link->next == 0x0);
  link->prev = prev;
  if (prev == 0x0) {
    link->next = list->head;
    if (list->head) {
      list->head->prev = link;
    } else {
      KASSERT_DBG(list->tail == 0x0);
      list->tail = link;
    }
    list->head = link;
  } else {
    if (prev->next) {
      prev->next->prev = link;
    } else {
      KASSERT_DBG(list->tail == prev);
      list->tail = link;
    }
    link->next = prev->next;
    prev->next = link;
  }
}

list_link_t* list_remove(list_t* list, list_link_t* link) {
  KASSERT_DBG(list->head != 0x0);
  KASSERT_DBG(list->tail != 0x0);
  if (list->head == link) {
    list_pop(list);
    return list->head;
  } else if (list->tail == link) {
    KASSERT_DBG(link->next == 0x0);
    KASSERT_DBG(link->prev != 0x0);
    list->tail = link->prev;
    KASSERT_DBG(list->tail != 0x0);
    KASSERT_DBG(list->tail->next == link);
    list->tail->next = 0x0;
    link->prev = 0x0;
    return NULL;
  } else {
    KASSERT_DBG(link->prev != 0x0);
    KASSERT_DBG(link->next != 0x0);
    list_link_t* next = link->next;
    link->prev->next = link->next;
    link->next->prev = link->prev;
    link->prev = link->next = 0x0;
    return next;
  }
}

int list_link_on_list(list_t* list, list_link_t* link) {
  if (SLOW_CONSISTENCY_CHECKS) {
    list_link_t* clink = list->head;
    while (clink) {
      if (clink == link) return 1;
      clink = clink->next;
    }
    KASSERT(link->next == 0x0);
    KASSERT(link->prev == 0x0);
    return 0;
  }
  return (list->head == link || link->next != 0x0 || link->prev != 0x0);
}

int list_empty(const list_t* list) {
  KASSERT_DBG((list->head == list->tail) ||
              (list->head != 0x0 && list->tail != 0x0));
  return (list->head == 0x0 && list->tail == 0x0);
}

int list_size(const list_t* list) {
  int size = 0;
  list_link_t* link = list->head;
  while (link) {
    size++;
    link = link->next;
  }
  return size;
}
