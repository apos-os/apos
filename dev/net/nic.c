// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#include "dev/net/nic.h"

#include <stdbool.h>

#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/refcount.h"
#include "net/neighbor_cache.h"
#include "proc/spinlock.h"

static list_t g_nics = LIST_INIT_STATIC;
static kspinlock_t g_nics_lock = KSPINLOCK_NORMAL_INIT_STATIC;

static void find_free_name(nic_t* nic, const char* name_prefix) {
  // Allow up to 999 NICs of each type.
  const int kMaxIndex = 1000;
  KASSERT(kstrlen(name_prefix) < NIC_MAX_NAME_LEN - 4);

  // Find a free name.  This is bananas inefficient.
  int idx;
  for (idx = 0; idx < kMaxIndex; ++idx) {
    ksprintf(nic->name, "%s%d", name_prefix, idx);
    bool collision = false;
    nic_t* iter = nic_first();
    while (iter) {
      if (kstrcmp(nic->name, iter->name) == 0) {
        collision = true;
        break;
      }
      nic_next(&iter);
    }
    if (!collision) {
      break;
    }
  }
  if (idx == kMaxIndex) {
    die("Too many NICs!  I can't deal!");
  }
}

void nic_init(nic_t* nic) {
  nic->lock = KSPINLOCK_NORMAL_INIT;
  nic->ref = REFCOUNT_INIT;
  nic->link = LIST_LINK_INIT;
  kmemset(&nic->name, 0, NIC_MAX_NAME_LEN);
  nic->type = NIC_UNKNOWN;
  kmemset(&nic->mac, 0, NIC_MAC_LEN);

  for (size_t i = 0; i < NIC_MAX_ADDRS; ++i) {
    kmemset(&nic->addrs[i], 0, sizeof(nic_addr_t));
    nic->addrs[i].a.addr.family = AF_UNSPEC;
    nic->addrs[i].state = NIC_ADDR_NONE;
  }
  nbr_cache_init(&nic->nbr_cache);
  nic->deleted = false;
}

void nic_create(nic_t* nic, const char* name_prefix) {
  char buf[NIC_MAC_PRETTY_LEN];
  find_free_name(nic, name_prefix);
  kspin_lock(&g_nics_lock);
  klogf("net: added NIC %s with MAC %s\n", nic->name,
        mac2str(nic->mac.addr, buf));
  list_push(&g_nics, &nic->link);
  kspin_unlock(&g_nics_lock);
}

void nic_delete(nic_t* nic) {
  KASSERT(!nic->deleted);

  kspin_lock(&g_nics_lock);
  nic->deleted = true;
  kspin_unlock(&g_nics_lock);
}

static void skip_deleted(nic_t** iter) {
  KASSERT_DBG(kspin_is_held(&g_nics_lock));
  while ((*iter) && (*iter)->deleted) {
    list_link_t* next_link = (*iter)->link.next;
    *iter = next_link ? container_of(next_link, nic_t, link) : NULL;
  }
}

nic_t* nic_first(void) {
  kspin_lock(&g_nics_lock);
  nic_t* nic = container_of(g_nics.head, nic_t, link);
  skip_deleted(&nic);
  if (nic) {
    refcount_inc(&nic->ref);
  }
  kspin_unlock(&g_nics_lock);
  return nic;
}

void nic_next(nic_t** iter) {
  kspin_lock(&g_nics_lock);
  list_link_t* next_link = (*iter)->link.next;
  nic_t* next = next_link ? container_of(next_link, nic_t, link) : NULL;
  skip_deleted(&next);
  if (next) {
    refcount_inc(&next->ref);
  }
  kspin_unlock(&g_nics_lock);
  nic_put(*iter);
  *iter = next;
}

nic_t* nic_get_nm(const char* name) {
  nic_t* iter = nic_first();
  while (iter) {
    if (kstrcmp(name, iter->name) == 0) {
      return iter;
    }
    nic_next(&iter);
  }
  return NULL;
}

void nic_put(nic_t* nic) {
  // Crude and incorrect safety check to catch refcount leaks.
  KASSERT(nic->ref.ref < 20);

  bool cleanup = false;
  if (refcount_dec(&nic->ref) == 0) {
    kspin_lock(&g_nics_lock);
    if (nic->deleted) {
      cleanup = true;
      list_remove(&g_nics, &nic->link);
    }
    kspin_unlock(&g_nics_lock);
  }

  if (cleanup) {
    klogf("net: deleting NIC %s\n", nic->name);
    nbr_cache_cleanup(&nic->nbr_cache);
    nic->ops->nic_cleanup(nic);
  }
}
