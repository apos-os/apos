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

#include "net/neighbor_cache.h"

#include "common/errno.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/eth/arp/arp.h"
#include "net/eth/mac.h"
#include "net/ip/icmpv6/ndp.h"
#include "net/neighbor_cache_ops.h"
#include "net/util.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/socket.h"

#define NBR_CACHE_INITIAL_SIZE 10
#define NBR_CACHE_TIMEOUT_MS (60 * 1000)

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

void nbr_cache_init(nbr_cache_t* cache) {
  htbl_init(&cache->cache, NBR_CACHE_INITIAL_SIZE);
  kthread_queue_init(&cache->wait);
}

static void entry_dtor(void* arg, uint32_t key, void* val) {
  nbr_cache_entry_t* entry = (nbr_cache_entry_t*)val;
  kfree(entry);
}

void nbr_cache_cleanup(nbr_cache_t* cache) {
  htbl_clear(&cache->cache, &entry_dtor, NULL);
  htbl_cleanup(&cache->cache);
}

// TODO(aoates): periodically go through the ARP caches and clean out expired
// entries, to keep them from growing unbounded.

int nbr_cache_lookup(nic_t* nic, netaddr_t addr, nbr_cache_entry_t* result,
                     int timeout_ms) {
  char macbuf[NIC_MAC_PRETTY_LEN];
  char addrbuf[NETADDR_PRETTY_LEN];
  const apos_ms_t start = get_time_ms();
  const apos_ms_t end = start + timeout_ms;

  uint32_t hash = netaddr_hash(&addr);
  kspin_lock(&nic->lock);
  apos_ms_t now;
  do {
    now = get_time_ms();
    void* value;
    if (htbl_get(&nic->nbr_cache.cache, hash, &value) == 0) {
      nbr_cache_entry_t* entry = (nbr_cache_entry_t*)value;
      if (now - entry->last_used <= NBR_CACHE_TIMEOUT_MS) {
        kmemcpy(result, entry, sizeof(nbr_cache_entry_t));
        kspin_unlock(&nic->lock);
        return 0;
      } else {
        KLOG(DEBUG,
             "Neighbor cache: ignoring expired entry %s -> %s (%d ms old)\n",
             netaddr2str(&addr, addrbuf), mac2str(entry->mac.addr, macbuf),
             now - entry->last_used);
      }
    }

    // If the entry didn't exist, or was expired, send a request and wait.
    switch (addr.family) {
      case ADDR_INET:
        arp_send_request(nic, addr.a.ip4.s_addr);
        break;

      case ADDR_INET6:
        ndp_send_request(nic, &addr.a.ip6);
        break;

      default:
        kspin_unlock(&nic->lock);
        return -EAFNOSUPPORT;
    }

    // TODO(aoates): retries after a timeout?  Or just let the upper layers deal
    // with it?

    if (timeout_ms > 0 && now < end) {
      int result = scheduler_wait_on_splocked(&nic->nbr_cache.wait, end - now,
                                              &nic->lock);
      if (result == SWAIT_TIMEOUT) {
        kspin_unlock(&nic->lock);
        return -ETIMEDOUT;
      } else if (result == SWAIT_INTERRUPTED) {
        kspin_unlock(&nic->lock);
        return -EINTR;
      }
    }
  } while (timeout_ms > 0 && now < end);

  kspin_unlock(&nic->lock);
  return -EAGAIN;
}

void nbr_cache_insert(nic_t* nic, netaddr_t addr, const uint8_t* mac) {
  char macbuf[NIC_MAC_PRETTY_LEN];
  char addrbuf[NETADDR_PRETTY_LEN];
  nbr_cache_entry_t* entry;
  void* val;

  uint32_t hash = netaddr_hash(&addr);
  kspin_lock(&nic->lock);
  if (htbl_get(&nic->nbr_cache.cache, hash, &val) == 0) {
    KLOG(DEBUG, "Neighbor cache: updating cache entry %s -> %s\n",
         netaddr2str(&addr, addrbuf), mac2str(mac, macbuf));
    entry = (nbr_cache_entry_t*)val;
  } else {
    KLOG(DEBUG, "Neighbor cache: inserting new cache entry %s -> %s\n",
         netaddr2str(&addr, addrbuf), mac2str(mac, macbuf));
    entry = (nbr_cache_entry_t*)kmalloc(sizeof(nbr_cache_entry_t));
    htbl_put(&nic->nbr_cache.cache, hash, entry);
  }
  kmemcpy(entry->mac.addr, mac, ETH_MAC_LEN);
  entry->last_used = get_time_ms();
  scheduler_wake_all(&nic->nbr_cache.wait);
  kspin_unlock(&nic->lock);
}

void nbr_cache_clear(nic_t* nic) {
  kspin_lock(&nic->lock);
  htbl_clear(&nic->nbr_cache.cache, &entry_dtor, NULL);
  kspin_unlock(&nic->lock);
}
