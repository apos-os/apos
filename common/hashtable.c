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

#include "common/kassert.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "kmalloc.h"

struct htbl_entry {
  uint32_t key;
  void* value;
  struct htbl_entry* next;
};

static inline uint32_t hash(htbl_t* tbl, uint32_t key) {
  return fnv_hash(key) % tbl->num_buckets;
}

void htbl_init(htbl_t* tbl, int buckets) {
  tbl->buckets = (htbl_entry_t**)kmalloc(sizeof(htbl_entry_t*) * buckets);
  for (int i = 0; i < buckets; ++i) {
    tbl->buckets[i] = 0x0;
  }
  tbl->num_buckets = buckets;
}

void htbl_cleanup(htbl_t* tbl) {
  for (int i = 0; i < tbl->num_buckets; ++i) {
    htbl_entry_t* e = tbl->buckets[i];
    while (e) {
      htbl_entry_t* next = e->next;
      kfree(e);
      e = next;
    }
  }
  kfree(tbl->buckets);
  tbl->buckets = 0x0;
  tbl->num_buckets = -1;
}

void htbl_put(htbl_t* tbl, uint32_t key, void* value) {
  const uint32_t bucket = hash(tbl, key);
  htbl_entry_t* e = tbl->buckets[bucket];
  while (e) {
    if (e->key == key) {
      e->value = value;
      return;
    }
    e = e->next;
  }

  // Add a new entry.
  e = (htbl_entry_t*)kmalloc(sizeof(htbl_entry_t));
  e->key = key;
  e->value = value;
  e->next = tbl->buckets[bucket];
  tbl->buckets[bucket] = e;
}

int htbl_get(htbl_t* tbl, uint32_t key, void** value) {
  const uint32_t bucket = hash(tbl, key);
  htbl_entry_t* e = tbl->buckets[bucket];
  while (e) {
    if (e->key == key) {
      *value = e->value;
      return 0;
    }
    e = e->next;
  }
  return -1;
}

int htbl_remove(htbl_t* tbl, uint32_t key) {
  const uint32_t bucket = hash(tbl, key);
  htbl_entry_t* e = tbl->buckets[bucket];
  htbl_entry_t* prev = 0;
  while (e) {
    if (e->key == key) {
      if (prev) {
        prev->next = e->next;
      } else {
        tbl->buckets[bucket] = e->next;
      }
      kfree(e);
      return 0;
    }
    prev = e;
    e = e->next;
  }
  return -1;
}
