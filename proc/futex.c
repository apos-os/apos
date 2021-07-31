// Copyright 2021 Andrew Oates.  All Rights Reserved.
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
#include "proc/futex.h"

#include "common/errno.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/time.h"
#include "memory/kmalloc.h"
#include "memory/vm.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"

#define FUTEX_TABLE_INITIAL_ENTRIES 10
static htbl_t g_futex_table;
static bool g_futex_initialized = false;
static kspinlock_t g_futex_lock = KSPINLOCK_NORMAL_INIT_STATIC;

typedef struct {
  kthread_queue_t queue;
  int waiters;
} futex_t;

static uint32_t futex_key(phys_addr_t addr) {
  return fnv_hash_array(&addr, sizeof(addr));
}

static void futex_init(futex_t* f) {
  kthread_queue_init(&f->queue);
  f->waiters = 0;
}

int futex_wait(uint32_t* uaddr, uint32_t val,
               const struct apos_timespec* timeout_relative) {
  phys_addr_t resolved;
  // TODO(SMP): lock the process's memory map.
  int result =
      vm_resolve_address(proc_current(), (addr_t)uaddr, sizeof(uint32_t),
                         /*is_write=*/false, /*is_user=*/true,
                         &resolved);
  if (result) return result;

  kspin_lock(&g_futex_lock);
  if (!g_futex_initialized) {
    htbl_init(&g_futex_table, FUTEX_TABLE_INITIAL_ENTRIES);
    g_futex_initialized = true;
  }

  // First check current value.
  // TODO(SMP): do a proper atomic operation here.
  // TODO(SMP): likely need some sort of barrier as well.
  uint32_t cur_val = *uaddr;
  if (cur_val != val) {
    kspin_unlock(&g_futex_lock);
    return -EAGAIN;
  }

  void* tbl_val;
  // TODO(aoates): make htbl support 64-bit keys natively.
  const uint32_t tbl_key = futex_key(resolved);
  futex_t* f = NULL;
  if (htbl_get(&g_futex_table, tbl_key, &tbl_val) < 0) {
    // No futex associated with this address yet.  Create one.
    // TODO(aoates): consider some sort of LRU queue to avoid constant futex
    // allocation/freeing.
    f = (futex_t*)kmalloc(sizeof(futex_t));
    futex_init(f);
    htbl_put(&g_futex_table, tbl_key, f);
  } else {
    f = (futex_t*)tbl_val;
  }

  KASSERT_DBG(f->waiters >= 0);
  f->waiters++;
  kspin_unlock(&g_futex_lock);

  long timeout_ms = timeout_relative ? timespec2ms(timeout_relative) : 0;
  // TODO(aoates): fix timeout handling so we don't need this hack.
  if (timeout_ms == 0 && timeout_relative != NULL) timeout_ms = 1;
  result = scheduler_wait_on_interruptable(&f->queue, timeout_ms);

  kspin_lock(&g_futex_lock);
  // Safety check --- table should be consistent.
  KASSERT_DBG(htbl_get(&g_futex_table, tbl_key, &tbl_val) == 0);
  KASSERT_DBG((futex_t*)tbl_val == f);
  f->waiters--;
  if (f->waiters == 0) {
    KASSERT(0 == htbl_remove(&g_futex_table, tbl_key));
    kfree(f);
  }
  kspin_unlock(&g_futex_lock);

  if (result == SWAIT_INTERRUPTED) {
    return -EINTR;
  } else if (result == SWAIT_TIMEOUT) {
    return -ETIMEDOUT;
  }
  KASSERT_DBG(result == SWAIT_DONE);

  return 0;
}

int futex_wake(uint32_t* uaddr, uint32_t val) {
  phys_addr_t resolved;
  // TODO(SMP): lock the process's memory map.
  int result =
      vm_resolve_address(proc_current(), (addr_t)uaddr, sizeof(uint32_t),
                         /*is_write=*/false, /*is_user=*/true,
                         &resolved);
  if (result) return result;

  kspin_lock(&g_futex_lock);
  if (!g_futex_initialized) {
    kspin_unlock(&g_futex_lock);
    return 0;
  }

  void* tbl_val;
  const uint32_t tbl_key = futex_key(resolved);
  if (htbl_get(&g_futex_table, tbl_key, &tbl_val) < 0) {
    // No futex associated with this address.  We're done.
    kspin_unlock(&g_futex_lock);
    return 0;
  }

  futex_t* f = (futex_t*)tbl_val;
  uint32_t woken = 0;
  while (woken < val && !kthread_queue_empty(&f->queue)) {
    scheduler_wake_one(&f->queue);
    woken++;
  }

  kspin_unlock(&g_futex_lock);
  return woken;
}

int futex_op(uint32_t* uaddr, int futex_op, uint32_t val,
             const struct apos_timespec* timeout, uint32_t* uaddr2,
             uint32_t val3) {
  switch (futex_op) {
    case APOS_FUTEX_WAIT:
      return futex_wait(uaddr, val, timeout);

    case APOS_FUTEX_WAKE:
      return futex_wake(uaddr, val);

    default:
      return -EINVAL;
  }
}
