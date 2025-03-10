// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#include "dev/net/tuntap.h"

#include "common/attributes.h"
#include "common/errno.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/math.h"
#include "dev/char_dev.h"
#include "dev/dev.h"
#include "dev/net/nic.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/eth/eth.h"
#include "net/ip/ip.h"
#include "net/ip/ip6.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "user/include/apos/dev.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/poll.h"

#define KLOG(lvl, msg, ...) klogfm(KL_NET, lvl, "tuntap: " msg, __VA_ARGS__)

#define MIN_BUFSIZE 128
#define ALL_FLAGS (TUNTAP_TAP_MODE | TUNTAP_TUN_MODE)

typedef struct {
  nic_t nic;
  apos_dev_t dev_id;
  char_dev_t chardev;
  ssize_t bufsize;
  int flags;

  // TODO(aoates): replace this with the base nic_t lock.
  kspinlock_t lock;
  list_t tx;
  ssize_t tx_queued;
  htbl_t multicast;

  pollable_t poll_event;
  kthread_queue_t wait;
} tuntap_dev_t;

static inline ALWAYS_INLINE bool is_tap(tuntap_dev_t* tt) {
  return tt->flags & TUNTAP_TAP_MODE;
}

static void gen_random_mac(nic_t* nic) {
  uint32_t rand = fnv_hash_addr((addr_t)nic);
  rand = fnv_hash_concat(rand, fnv_hash_string(nic->name));
  rand = fnv_hash_concat(rand, fnv_hash(get_time_ms()));
  nic->mac.addr[0] = 2;  // Locally-administered bit.
  nic->mac.addr[1] = rand;
  nic->mac.addr[2] = rand >> 8;
  nic->mac.addr[3] = rand >> 16;
  nic->mac.addr[4] = rand >> 24;
  nic->mac.addr[5] = fnv_hash(rand);
}

// NIC operations.
static int tuntap_nic_tx(nic_t* nic, pbuf_t* buf);
static void tuntap_nic_cleanup(nic_t* nic);
static void tuntap_mc_sub(nic_t* nic, const nic_mac_t* mac);
static void tuntap_mc_unsub(nic_t* nic, const nic_mac_t* mac);

static nic_ops_t tuntap_nic_ops = {
  &tuntap_nic_tx,
  &tuntap_nic_cleanup,
  &tuntap_mc_sub,
  &tuntap_mc_unsub,
};

// Chardev operations.
static int tuntap_cd_read(struct char_dev* dev, void* buf, size_t len,
                          int flags);
static int tuntap_cd_write(struct char_dev* dev, const void* buf, size_t len,
                           int flags);
static int tuntap_cd_poll(struct char_dev* dev, short event_mask,
                          poll_state_t* poll);

static short tuntap_poll_events(const tuntap_dev_t* tt) {
  KASSERT_DBG(kspin_is_held(&tt->lock));
  short events = KPOLLOUT;
  if (!list_empty(&tt->tx)) {
    events |= KPOLLIN;
  }
  return events;
}

nic_t* tuntap_create(ssize_t bufsize, int flags, apos_dev_t* id) {
  if ((flags & ~ALL_FLAGS) != 0) {
    KLOG(INFO, "unsupported flags 0x%x\n", flags);
    return NULL;
  }
  if (!(flags & TUNTAP_TAP_MODE) && !(flags & TUNTAP_TUN_MODE)) {
    KLOG(INFO, "bad flags (must set TAP OR TUN mode): 0x%x\n", flags);
    return NULL;
  }
  if ((flags & TUNTAP_TAP_MODE) && (flags & TUNTAP_TUN_MODE)) {
    KLOG(INFO, "incompatible flags (TAP and TUN mode): 0x%x\n", flags);
    return NULL;
  }
  if (bufsize <= MIN_BUFSIZE || !id) {
    return NULL;
  }

  tuntap_dev_t* tt = KMALLOC(tuntap_dev_t);
  tt->bufsize = bufsize;
  tt->flags = flags;
  tt->lock = KSPINLOCK_NORMAL_INIT;
  tt->tx = LIST_INIT;
  tt->tx_queued = 0;
  htbl_init(&tt->multicast, 5);
  kthread_queue_init(&tt->wait);
  poll_init_event(&tt->poll_event);

  // Create the character device first.
  tt->dev_id = kmakedev(is_tap(tt) ? DEVICE_MAJOR_TAP : DEVICE_MAJOR_TUN,
                        DEVICE_ID_UNKNOWN);
  tt->chardev.read = &tuntap_cd_read;
  tt->chardev.write = &tuntap_cd_write;
  tt->chardev.poll = &tuntap_cd_poll;
  tt->chardev.dev_data = tt;

  // Initialize the NIC.
  nic_init(&tt->nic);
  tt->nic.type = is_tap(tt) ? NIC_ETHERNET : NIC_TUN;
  gen_random_mac(&tt->nic);
  tt->nic.ops = &tuntap_nic_ops;

  // Register the block device and NIC.
  int result = dev_register_char(&tt->chardev, &tt->dev_id);
  if (result) {
    KLOG(WARNING, "unable to create TUN/TAP chardev: %s\n", errorname(-result));
    return NULL;
  }
  *id = tt->dev_id;

  // Initialize the NIC.
  nic_create(&tt->nic, is_tap(tt) ? "tap" : "tun");
  KLOG(INFO, "created TUN/TAP device %s\n", tt->nic.name);

  return &tt->nic;
}

int tuntap_destroy(apos_dev_t id) {
  char_dev_t* cd = dev_get_char(id);
  if (!cd) {
    return -ENOENT;
  }

  tuntap_dev_t* tt = (tuntap_dev_t*)cd->dev_data;
  // TODO(aoates): ensure no open users of the chardev are left.
  int result = dev_unregister_char(tt->dev_id);
  if (result) {
    KLOG(ERROR, "unable to delete TUN/TAP device %s: %s\n", tt->nic.name,
         errorname(-result));
    return result;
  }
  poll_trigger_event(&tt->poll_event, KPOLLNVAL);
  poll_assert_empty_event(&tt->poll_event);

  // TODO(aoates): redo NIC refcounting and deletion system, this is strange and
  // brittle.
  nic_delete(&tt->nic);
  nic_put(&tt->nic);
  return 0;
}

static int tuntap_nic_tx(nic_t* nic, pbuf_t* buf) {
  tuntap_dev_t* tt = (tuntap_dev_t*)nic;
  kspin_lock(&tt->lock);
  if (tt->tx_queued + (ssize_t)buf->total_len > tt->bufsize) {
    kspin_unlock(&tt->lock);
    KLOG(DEBUG, "TUN/TAP dropping %zu bytes (tx buffer full)\n",
         buf->total_len);
    pbuf_free(buf);
    return 0;
  }
  list_push(&tt->tx, &buf->link);
  tt->tx_queued += buf->total_len;
  scheduler_wake_one(&tt->wait);
  poll_trigger_event(&tt->poll_event, tuntap_poll_events(tt));
  kspin_unlock(&tt->lock);
  return 0;
}

static void tuntap_nic_cleanup(nic_t* nic) {
  tuntap_dev_t* tt = (tuntap_dev_t*)nic;

  while (!list_empty(&tt->tx)) {
    list_link_t* link = list_pop(&tt->tx);
    pbuf_t* pb = container_of(link, pbuf_t, link);
    tt->tx_queued -= pb->total_len;
    pbuf_free(pb);
  }
  KASSERT_DBG(tt->tx_queued == 0);
  htbl_cleanup(&tt->multicast);
  kfree(tt);
}

static void tuntap_mc_sub(nic_t* nic, const nic_mac_t* mac) {
  tuntap_dev_t* tt = (tuntap_dev_t*)nic;
  kspin_lock(&tt->lock);
  htbl_put(&tt->multicast, fnv_hash_array(mac->addr, NIC_MAC_LEN), NULL);
  kspin_unlock(&tt->lock);
}

static void tuntap_mc_unsub(nic_t* nic, const nic_mac_t* mac) {
  tuntap_dev_t* tt = (tuntap_dev_t*)nic;
  uint32_t hash = fnv_hash_array(mac->addr, NIC_MAC_LEN);
  kspin_lock(&tt->lock);
  if (htbl_remove(&tt->multicast, hash) != 0) {
    KLOG(
        WARNING,
        "TUN/TAP: unable to unsubscribe to MAC addr on %s (not subscribed)\n",
        nic->name);
  }
  kspin_unlock(&tt->lock);
}

bool tuntap_mc_subscribed(nic_t* nic, const nic_mac_t* mac) {
  tuntap_dev_t* tt = (tuntap_dev_t*)nic;
  kspin_lock(&tt->lock);
  void* unused_val;
  int result = htbl_get(&tt->multicast, fnv_hash_array(mac->addr, NIC_MAC_LEN),
                        &unused_val);
  kspin_unlock(&tt->lock);
  return (result == 0);
}

static int tuntap_cd_read(struct char_dev* dev, void* buf, size_t len,
                          int flags) {
  tuntap_dev_t* tt = (tuntap_dev_t*)dev->dev_data;
  KASSERT_DBG(&tt->chardev == dev);

  kspin_lock(&tt->lock);
  while (list_empty(&tt->tx)) {
    if (flags & VFS_O_NONBLOCK) {
      kspin_unlock(&tt->lock);
      return -EAGAIN;
    }

    int result = scheduler_wait_on_splocked(&tt->wait, -1, &tt->lock);
    if (result == SWAIT_INTERRUPTED) {
      kspin_unlock(&tt->lock);
      return -EINTR;
    }
    KASSERT_DBG(result == SWAIT_DONE);
  }

  list_link_t* link = list_pop(&tt->tx);
  pbuf_t* pb = container_of(link, pbuf_t, link);
  tt->tx_queued -= pb->total_len;
  KASSERT_DBG(tt->tx_queued >= 0);
  kspin_unlock(&tt->lock);

  size_t read_len = min(len, pbuf_size(pb));
  kmemcpy(buf, pbuf_getc(pb), read_len);
  pbuf_free(pb);
  return read_len;
}

static int tuntap_cd_write(struct char_dev* dev, const void* buf, size_t len,
                           int flags) {
  tuntap_dev_t* tt = (tuntap_dev_t*)dev->dev_data;
  KASSERT_DBG(&tt->chardev == dev);
  pbuf_t* pb = pbuf_create(sizeof(eth_hdr_t) /* unused */, len);
  kmemcpy(pbuf_get(pb), buf, len);
  if (is_tap(tt)) {
    const eth_hdr_t* eth_hdr = (const eth_hdr_t*)pbuf_getc(pb);
    if (eth_hdr->mac_dst[0] & 0x01) {
      uint32_t hash = fnv_hash_array(eth_hdr->mac_dst, NIC_MAC_LEN);
      kspin_lock(&tt->lock);
      void* unused_val;
      bool allow = (htbl_get(&tt->multicast, hash, &unused_val) == 0);
      kspin_unlock(&tt->lock);
      if (!allow) {
        char mac_pretty[NIC_MAC_PRETTY_LEN];
        KLOG(DEBUG2, "TAP: ignoring multicast packet to %s\n",
             mac2str(eth_hdr->mac_dst, mac_pretty));
        pbuf_free(pb);
        return len;
      }
    }
    eth_recv(&tt->nic, pb);
  } else {
    int version = ((uint8_t*)buf)[0] >> 4;
    if (version == 4) {
      ip_recv(&tt->nic, pb);
    } else if (version == 6) {
      ip6_recv(&tt->nic, pb);
    } else {
      KLOG(WARNING, "TUN: bad IP packet version %d, dropping packet\n",
           version);
      pbuf_free(pb);
      return -EAFNOSUPPORT;
    }
  }
  return len;
}

static int tuntap_cd_poll(struct char_dev* dev, short event_mask,
                          poll_state_t* poll) {
  tuntap_dev_t* tt = (tuntap_dev_t*)dev->dev_data;
  KASSERT_DBG(&tt->chardev == dev);

  kspin_lock(&tt->lock);
  int result;
  const short masked_events = tuntap_poll_events(tt) & event_mask;
  if (masked_events || !poll) {
    result = masked_events;
  } else {
    result = poll_add_event(poll, &tt->poll_event, event_mask);
  }
  kspin_unlock(&tt->lock);
  return result;
}
