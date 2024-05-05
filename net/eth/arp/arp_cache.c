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

#include "net/eth/arp/arp_cache.h"

#include "common/errno.h"
#include "common/hashtable.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/eth/mac.h"
#include "net/eth/arp/arp.h"
#include "net/util.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"

#define ARP_CACHE_INITIAL_SIZE 10
#define ARP_CACHE_TIMEOUT_MS (60 * 1000)

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

void arp_cache_init(arp_cache_t* cache) {
  htbl_init(&cache->cache, ARP_CACHE_INITIAL_SIZE);
  kthread_queue_init(&cache->wait);
}

static void entry_dtor(void* arg, uint32_t key, void* val) {
  arp_cache_entry_t* entry = (arp_cache_entry_t*)val;
  kfree(entry);
}

void arp_cache_cleanup(arp_cache_t* cache) {
  htbl_clear(&cache->cache, &entry_dtor, NULL);
  htbl_cleanup(&cache->cache);
}

// TODO(aoates): periodically go through the ARP caches and clean out expired
// entries, to keep them from growing unbounded.

int arp_cache_lookup(nic_t* nic, in_addr_t addr, arp_cache_entry_t* result,
                     int timeout_ms) {
  char macbuf[NIC_MAC_PRETTY_LEN];
  char inetbuf[INET_PRETTY_LEN];
  const apos_ms_t start = get_time_ms();
  const apos_ms_t end = start + timeout_ms;

  kspin_lock(&nic->lock);
  apos_ms_t now;
  do {
    now = get_time_ms();
    void* value;
    if (htbl_get(&nic->arp_cache.cache, addr, &value) == 0) {
      arp_cache_entry_t* entry = (arp_cache_entry_t*)value;
      if (now - entry->last_used <= ARP_CACHE_TIMEOUT_MS) {
        kmemcpy(result, entry, sizeof(arp_cache_entry_t));
        kspin_unlock(&nic->lock);
        return 0;
      } else {
        KLOG(DEBUG, "ARP: ignoring expired entry %s -> %s (%d ms old)\n",
             inet2str(addr, inetbuf), mac2str(entry->mac.addr, macbuf),
             now - entry->last_used);
      }
    }

    // If the entry didn't exist, or was expired, send a request and wait.
    arp_send_request(nic, addr);
    // TODO(aoates): retries after a timeout?  Or just let the upper layers deal
    // with it?

    if (timeout_ms > 0 && now < end) {
      int result = scheduler_wait_on_splocked(&nic->arp_cache.wait, end - now,
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

void arp_cache_insert(nic_t* nic, in_addr_t addr, const uint8_t* mac) {
  char macbuf[NIC_MAC_PRETTY_LEN];
  char inetbuf[INET_PRETTY_LEN];
  arp_cache_entry_t* entry;
  void* val;

  kspin_lock(&nic->lock);
  if (htbl_get(&nic->arp_cache.cache, addr, &val) == 0) {
    KLOG(DEBUG, "ARP: updating cache entry %s -> %s\n",
         inet2str(addr, inetbuf), mac2str(mac, macbuf));
    entry = (arp_cache_entry_t*)val;
  } else {
    KLOG(DEBUG, "ARP: inserting new cache entry %s -> %s\n",
         inet2str(addr, inetbuf), mac2str(mac, macbuf));
    entry = (arp_cache_entry_t*)kmalloc(sizeof(arp_cache_entry_t));
    htbl_put(&nic->arp_cache.cache, addr, entry);
  }
  kmemcpy(entry->mac.addr, mac, ETH_MAC_LEN);
  entry->last_used = get_time_ms();
  scheduler_wake_all(&nic->arp_cache.wait);
  kspin_unlock(&nic->lock);
}
