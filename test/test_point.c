// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "test/test_point.h"

#include "common/attributes.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/spinlock.h"
#include "proc/scheduler.h"

typedef struct {
  test_point_cb_t cb;
  void* arg;
  int count;
  int refcount;
} test_point_entry_t;

// Global spinlock for hashtable and entry refcounts.
static kspinlock_t gtp_lock = KSPINLOCK_NORMAL_INIT_STATIC;
static kthread_queue_t gtp_queue GUARDED_BY(gtp_lock);

// All entries.
static htbl_t gtp_entries;

static bool gtp_init;

static void maybe_init(void) {
  if (gtp_init) {
    return;
  }

  htbl_init(&gtp_entries, 5);
  kthread_queue_init(&gtp_queue);
  gtp_init = true;
}

static inline ALWAYS_INLINE uint32_t tpkey(const char* name) {
  return fnv_hash_string(name);
}

void test_point_add(const char* name, test_point_cb_t cb, void* arg) {
  kspin_lock(&gtp_lock);
  maybe_init();
  uint32_t key = tpkey(name);
  void* val;
  KASSERT(htbl_get(&gtp_entries, key, &val) != 0);

  test_point_entry_t* entry = KMALLOC(test_point_entry_t);
  entry->cb = cb;
  entry->arg = arg;
  entry->count = 0;
  entry->refcount = 0;
  htbl_put(&gtp_entries, key, entry);
  kspin_unlock(&gtp_lock);
}

int test_point_remove(const char* name) {
  kspin_lock(&gtp_lock);
  KASSERT(gtp_init);
  uint32_t key = tpkey(name);
  void* val;
  KASSERT(htbl_get(&gtp_entries, key, &val) == 0);

  test_point_entry_t* entry = (test_point_entry_t*)val;
  while (entry->refcount > 0) {
    scheduler_wait_on_splocked(&gtp_queue, -1, &gtp_lock);
  }

  int count = entry->count;
  KASSERT(htbl_remove(&gtp_entries, key) == 0);
  kfree(entry);
  kspin_unlock(&gtp_lock);
  return count;
}

void test_point_run(const char* name) {
  kspin_lock(&gtp_lock);
  // Fast path bail.
  if (!gtp_init || htbl_size(&gtp_entries) == 0) {
    kspin_unlock(&gtp_lock);
    return;
  }

  maybe_init();
  uint32_t key = tpkey(name);
  void* val;
  if (htbl_get(&gtp_entries, key, &val) == 0) {
    test_point_entry_t* entry = (test_point_entry_t*)val;
    entry->refcount++;
    int count = entry->count++;
    KASSERT_DBG(entry->refcount > 0);
    kspin_unlock(&gtp_lock);

    entry->cb(name, count, entry->arg);

    kspin_lock(&gtp_lock);
    KASSERT_DBG(entry->refcount > 0);
    if (--entry->refcount == 0) {
      scheduler_wake_all(&gtp_queue);
    }
  }
  kspin_unlock(&gtp_lock);
}

int test_point_count(void) {
  kspin_lock(&gtp_lock);
  int size = gtp_init ? htbl_size(&gtp_entries) : 0;
  kspin_unlock(&gtp_lock);
  return size;
}
