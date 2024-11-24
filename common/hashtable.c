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
#include "proc/preemption_hook.h"

#define GROW_THRESHOLD 0.75
#define GROW_RATIO 2

#if PREEMPTION_INDUCE_LEVEL_HTBL > 0
# define preempt() sched_preempt_me(PREEMPTION_INDUCE_LEVEL_HTBL)
#else
# define preempt()
#endif

struct htbl_entry {
  htbl_key_t key;
  void* value;
  struct htbl_entry* next;
};

static inline uint32_t hash_num_buckets(int num_buckets, htbl_key_t key) {
  // On 32-bit systems, avoid a 64-bit division by truncating the hash.
#if ARCH_IS_64_BIT
  return fnv64_hash(key) % num_buckets;
#else
  return ((uint32_t)fnv64_hash(key)) % num_buckets;
#endif
}

static inline uint32_t hash(const htbl_t* tbl, htbl_key_t key) {
  return hash_num_buckets(tbl->num_buckets, key);
}

void htbl_resize(htbl_t* tbl, int new_size) {
  htbl_entry_t** new_buckets = (htbl_entry_t**)alloc_alloc(
      tbl->alloc, sizeof(htbl_entry_t*) * new_size, sizeof(void*));
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

  alloc_free(tbl->alloc, tbl->buckets);

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
  htbl_init_alloc(tbl, buckets, &kDefaultAlloc);
}

void htbl_init_alloc(htbl_t* tbl, int buckets, const allocator_t* alloc) {
  tbl->alloc = alloc;
  tbl->buckets = (htbl_entry_t**)alloc_alloc(
      tbl->alloc, sizeof(htbl_entry_t*) * buckets, sizeof(void*));
  for (int i = 0; i < buckets; ++i) {
    tbl->buckets[i] = 0x0;
  }
  tbl->num_buckets = buckets;
  tbl->num_entries = 0;
  tbl->generation = 0;
}

void htbl_cleanup(htbl_t* tbl) {
  for (int i = 0; i < tbl->num_buckets; ++i) {
    htbl_entry_t* e = tbl->buckets[i];
    while (e) {
      htbl_entry_t* next = e->next;
      alloc_free(tbl->alloc, e);
      e = next;
    }
  }
  alloc_free(tbl->alloc, tbl->buckets);
  tbl->buckets = 0x0;
  tbl->num_buckets = -1;
}

void htbl_put(htbl_t* tbl, htbl_key_t key, void* value) {
  uint16_t g = tbl->generation;
  preempt();
  KASSERT(tbl->generation == g);
  tbl->generation++;

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
  e = (htbl_entry_t*)alloc_alloc(tbl->alloc, sizeof(htbl_entry_t),
                                 sizeof(void*));
  e->key = key;
  e->value = value;
  e->next = tbl->buckets[bucket];
  tbl->buckets[bucket] = e;
  tbl->num_entries++;

  maybe_grow(tbl);
}

int htbl_get(const htbl_t* tbl, htbl_key_t key, void** value) {
  uint16_t g = tbl->generation;
  preempt();
  KASSERT(tbl->generation == g);

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

int htbl_remove(htbl_t* tbl, htbl_key_t key) {
  uint16_t g = tbl->generation;
  preempt();
  KASSERT(tbl->generation == g);
  tbl->generation++;

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
      alloc_free(tbl->alloc, e);
      tbl->num_entries--;
      return 0;
    }
    prev = e;
    e = e->next;
  }
  return -1;
}

void htbl_iterate(const htbl_t* tbl, void (*func)(void*, htbl_key_t, void*),
                  void* arg) {
  uint16_t g = tbl->generation;
  preempt();
  KASSERT(tbl->generation == g);

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

void htbl_clear(htbl_t* tbl, void (*dtor)(void*, htbl_key_t, void*), void* arg) {
  int counter = tbl->num_entries;
  for (int i = 0; i < tbl->num_buckets; ++i) {
    while (tbl->buckets[i]) {
      htbl_entry_t* e = tbl->buckets[i];
      tbl->buckets[i] = e->next;
      tbl->num_entries--;
      dtor(arg, e->key, e->value);
      alloc_free(tbl->alloc, e);
      counter--;
    }
  }
  // TODO(aoates): should we shrink the table back down?
  KASSERT_DBG(counter == 0);
}

int htbl_filter(htbl_t* tbl, bool (*pred)(void*, htbl_key_t, void*), void* arg) {
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
        alloc_free(tbl->alloc, e);
      } else {
        prev_ptr = &e->next;
      }
      e = *prev_ptr;
    }
  }
  // TODO(aoates): should we shrink the table back down?
  return removed;
}

int htbl_size(const htbl_t* tbl) {
  return tbl->num_entries;
}

int htbl_num_buckets(const htbl_t* tbl) {
  return tbl->num_buckets;
}
