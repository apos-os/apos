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
#include "memory/kmalloc.h"

#define GROW_THRESHOLD 0.75
#define GROW_RATIO 2

struct htbl_entry {
  uint32_t key;
  void* value;
  struct htbl_entry* next;
};

static inline uint32_t hash_num_buckets(int num_buckets, uint32_t key) {
  return fnv_hash(key) % num_buckets;
}

static inline uint32_t hash(htbl_t* tbl, uint32_t key) {
  return hash_num_buckets(tbl->num_buckets, key);
}

void htbl_resize(htbl_t* tbl, int new_size) {
  htbl_entry_t** new_buckets =
      (htbl_entry_t**)kmalloc(sizeof(htbl_entry_t*) * new_size);
  if (!new_buckets) return;

  for (int i = 0; i < new_size; ++i) {
    new_buckets[i] = 0x0;
  }

  // Copy all the old entries over.
  for (int i = 0; i < tbl->num_buckets; ++i) {
    while (tbl->buckets[i]) {
      htbl_entry_t* e = tbl->buckets[i];
      tbl->buckets[i] = e->next;

      const uint32_t new_bucket = hash_num_buckets(new_size, e->key);
      e->next = new_buckets[new_bucket];
      new_buckets[new_bucket] = e;
    }
  }

  kfree(tbl->buckets);

  tbl->buckets = new_buckets;
  tbl->num_buckets = new_size;
}

static void maybe_grow(htbl_t* tbl) {
  if (tbl->num_entries >= tbl->num_buckets * GROW_THRESHOLD) {
    const int new_size = tbl->num_buckets * GROW_RATIO;
    htbl_resize(tbl, new_size);
  }
}

void htbl_init(htbl_t* tbl, int buckets) {
  tbl->buckets = (htbl_entry_t**)kmalloc(sizeof(htbl_entry_t*) * buckets);
  for (int i = 0; i < buckets; ++i) {
    tbl->buckets[i] = 0x0;
  }
  tbl->num_buckets = buckets;
  tbl->num_entries = 0;
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
  tbl->num_entries++;

  maybe_grow(tbl);
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
      tbl->num_entries--;
      return 0;
    }
    prev = e;
    e = e->next;
  }
  return -1;
}

void htbl_iterate(htbl_t* tbl, void (*func)(void*, uint32_t, void*),
                  void* arg) {
  int counter = 0;
  for (int i = 0; i < tbl->num_buckets; ++i) {
    htbl_entry_t* e = tbl->buckets[i];
    while (e) {
      counter++;
      func(arg, e->key, e->value);
      e = e->next;
    }
  }
  KASSERT_DBG(counter == tbl->num_entries);
}

void htbl_clear(htbl_t* tbl, void (*dtor)(void*, uint32_t, void*), void* arg) {
  int counter = tbl->num_entries;
  for (int i = 0; i < tbl->num_buckets; ++i) {
    while (tbl->buckets[i]) {
      htbl_entry_t* e = tbl->buckets[i];
      tbl->buckets[i] = e->next;
      tbl->num_entries--;
      dtor(arg, e->key, e->value);
      kfree(e);
      counter--;
    }
  }
  // TODO(aoates): should we shrink the table back down?
  KASSERT_DBG(counter == 0);
}

int htbl_filter(htbl_t* tbl, bool (*pred)(void*, uint32_t, void*), void* arg) {
  int removed = 0;
  for (int i = 0; i < tbl->num_buckets; ++i) {
    htbl_entry_t** prev_ptr = &tbl->buckets[i];
    htbl_entry_t* e = tbl->buckets[i];
    while (e) {
      bool result = pred(arg, e->key, e->value);
      if (!result) {
        removed++;
        *prev_ptr = e->next;
        tbl->num_entries--;
        kfree(e);
      } else {
        prev_ptr = &e->next;
      }
      e = *prev_ptr;
    }
  }
  // TODO(aoates): should we shrink the table back down?
  return removed;
}

int htbl_size(htbl_t* tbl) {
  return tbl->num_entries;
}

int htbl_num_buckets(htbl_t* tbl) {
  return tbl->num_buckets;
}
