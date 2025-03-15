// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "sanitizers/tsan/tsan_sync.h"

#define HASH_H_DISABLE_TSAN

#include "common/hash.h"
#include "common/kassert.h"
#include "common/kstring-tsan.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "sanitizers/tsan/shadow_cell.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_lock.h"
#include "sanitizers/tsan/tsan_spinlock.h"

// We only support 32-bit atomic accesses currently for efficiency.
#define TSAN_SYNC_OBJ_SIZE 4

// Free list of sync objects.
static tsan_sync_t* g_sync_freelist = NULL;

typedef struct {
  tsan_sync_t* entries;
} sync_table_bucket_t;

// Hash table of sync objects.  Map addr_t -> tsan_sync_t* (linked list).
static sync_table_bucket_t* const g_sync_table =
    (sync_table_bucket_t*)TSAN_SYNC_OBJ_TABLE_START;

// Does the lookup of the given address in the sync object table.
static inline ALWAYS_INLINE sync_table_bucket_t* get_sync(addr_t addr) {
  uint32_t hash = fnv_hash_addr(addr);
  return &g_sync_table[hash % (TSAN_SYNC_OBJ_TABLE_LEN / sizeof(tsan_sync_t*))];
}

// Given an address, return the bucket it belongs in and the entry (if it
// exists).
static inline ALWAYS_INLINE
tsan_sync_t* find_sync(addr_t addr, tsan_sync_t** prev,
                       sync_table_bucket_t** bucket_out) {
  sync_table_bucket_t* bucket = get_sync(addr);
  tsan_page_metadata_t* pmd = tsan_get_page_md(addr);
  // Skip the search if we know there are no sync objects in this page.
  tsan_sync_t* entry = pmd->num_sync_objs ? bucket->entries : NULL;
  *prev = NULL;
  while (entry) {
    if (entry->addr == addr) break;
    *prev = entry;
    entry = entry->next;
  }

  *bucket_out = bucket;
  return entry;
}

// Allocate a sync object.
static tsan_sync_t* alloc_sync(void) {
  if (g_sync_freelist) {
    tsan_sync_t* result = g_sync_freelist;
    g_sync_freelist = g_sync_freelist->next;
    return result;
  }

  // Need to refill the freelist.
  phys_addr_t page_phys = page_frame_alloc();
  addr_t page = phys2virt(page_phys);
  const int kNumSyncs = PAGE_SIZE / sizeof(tsan_sync_t);
  tsan_sync_t* entries = (tsan_sync_t*)page;
  for (int i = 0; i < kNumSyncs; ++i) {
    kmemset_no_tsan(&entries[i], 0, sizeof(tsan_sync_t));
    if (i < kNumSyncs - 1) {
      entries[i].next = &entries[i + 1];
    }
  }
  g_sync_freelist = &entries[0];
  return alloc_sync();
}

tsan_sync_t* tsan_sync_get(addr_t addr, size_t access_size, bool create) {
  KASSERT(access_size == TSAN_SYNC_OBJ_SIZE);
  KASSERT(addr % TSAN_SYNC_OBJ_SIZE == 0);

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  sync_table_bucket_t* bucket = NULL;
  tsan_page_metadata_t* pmd = tsan_get_page_md(addr);
  tsan_sync_t* unused_prev = NULL;
  tsan_sync_t* entry = find_sync(addr, &unused_prev, &bucket);

  if (!entry && !create) {
    POP_INTERRUPTS_NO_TSAN();
    return NULL;
  } else if (!entry) {
    entry = alloc_sync();
    entry->addr = addr;
    entry->spin = TSAN_SPINLOCK_INIT;
    tsan_lock_init(&entry->lock);
    entry->next = bucket->entries;
    bucket->entries = entry;
    pmd->num_sync_objs++;
  } else {
    KASSERT_DBG(pmd->num_sync_objs > 0);
  }
  POP_INTERRUPTS_NO_TSAN();

  return entry;
}

static void free_range(tsan_page_metadata_t* pmd, addr_t start, addr_t end) {
  // Align the start up and end down to the minimum sync object size.  By
  // definition, any smaller chunks on each end can't be associated with sync
  // objects.
  start = align_up(start, TSAN_SYNC_OBJ_SIZE);
  end = end & ~(TSAN_SYNC_OBJ_SIZE - 1);
  for (; start < end; start += TSAN_SYNC_OBJ_SIZE) {
    sync_table_bucket_t* bucket = NULL;
    tsan_sync_t* prev;
    tsan_sync_t* sync = find_sync(start, &prev, &bucket);
    if (sync) {
      if (prev) {
        prev->next = sync->next;
      } else {
        KASSERT_DBG(bucket->entries == sync);
        bucket->entries = sync->next;
      }
      sync->addr = 0;
      sync->next = g_sync_freelist;
      g_sync_freelist = sync;
      pmd->num_sync_objs--;
    }
  }
}

void tsan_sync_free(addr_t range_start, size_t len) {
  addr_t range_end = range_start + len;
  // Doesn't actually need to be atomic across the whole range, but don't bother
  // pushing and popping each iteration.  If we made pmd atomically accessible
  // then the critical section could be reduced.
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  for (addr_t addr = range_start; addr < range_end; addr += PAGE_SIZE) {
    tsan_page_metadata_t* pmd = tsan_get_page_md(addr);
    if (pmd->num_sync_objs == 0) continue;

    // Process to the end of the page, or end of the range, whichever is first.
    addr_t chunk_end = min(addr2page(addr) + PAGE_SIZE, range_end);
    free_range(pmd, addr, chunk_end);
  }
  POP_INTERRUPTS_NO_TSAN();
}
