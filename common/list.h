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

// Doubly linked list.
//
// Usage:
// Embed a list_link_t in each value structure.
//
// typedef struct {
//   int x;
//   list_link_t link;
// } node_t;
//
// list_t list = LIST_INIT;
//
// node_t nodes[10];
// for (int i = 0; i < 10; ++i) {
//   nodes[i].x = i;
//   nodes[i].link = LIST_LINK_INIT;
//   list_push(&list, &nodes[i]);
// }
//
// KASSERT(&nodes[i] == list_pop(&list));
#ifndef APOO_COMMON_LIST_H
#define APOO_COMMON_LIST_H

#include <stddef.h>

// Given a pointer to a struct member, the name of the containing type, and the
// name of the member, return a pointer to the containing object.
#define container_of(ptr, type, member_name) \
    ({typeof(((type*)0x0)->member_name)* __member = (ptr); \
      __member == 0x0 ? 0x0 : \
       ((type*)((char*)(__member) - offsetof(type, member_name)));})

// Helper macros to iterate over a list.  Example:
//
// list_t some_list;
// FOR_EACH_LIST(link_iter, &some_list) {
//   node_t* val = LIST_ENTRY(link_iter, node_t, link);
//   klogf(val->x);
// }
//
// is roughly equivalent to the following C++-style iteration,
// for (node_t* val : some_list) { ... }
#define FOR_EACH_LIST(iter_name, list_expr)                           \
  for (list_link_t* iter_name = (list_expr)->head; iter_name != NULL; \
       iter_name = iter_name->next)
#define LIST_ENTRY(iter_name, parent_type, link_field_name) \
    container_of(iter_name, parent_type, link_field_name)

// A link in the list.  Embed this in your value struct.
typedef struct list_link {
  struct list_link* prev;
  struct list_link* next;
} list_link_t;

// The list data itself.
typedef struct {
  struct list_link* head;
  struct list_link* tail;
} list_t;

// Initializer for an empty link and list.
extern const list_link_t LIST_LINK_INIT;
extern const list_t LIST_INIT;

// Static initializer for list_t for statically initializing global variables.
#define LIST_INIT_STATIC {0x0, 0x0}

// Push a new link onto the back of the given list.
void list_push(list_t* list, list_link_t* link);

// Insert the given element in the list after prev.  If prev == NULL, then the
// new link is inserted at the list head.
void list_insert(list_t* list, list_link_t* prev, list_link_t* link);

// Pop a link off the front of the given list.  Returns NULL if the list is
// empty.
list_link_t* list_pop(list_t* list);

// Remove a link from the given list.  Returns the next link (the one after the
// link that was just deleted), or NULL if it was the last link in the list.
list_link_t* list_remove(list_t* list, list_link_t* link);

// Return non-zero if the given link is on the list.
//
// Note: this does NOT traverse the list in question, only checks the link's
// pointers.  So this will not work properly if a link can be on more than one
// list.
int list_link_on_list(list_t* list, list_link_t* link);

// Returns non-zero if the list is empty.
int list_empty(const list_t* list);

// Returns the size of the list.
int list_size(const list_t* list);

#endif
