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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/math.h"
#include "dev/char_dev.h"
#include "dev/dev.h"
#include "dev/net/nic.h"
#include "memory/kmalloc.h"
#include "net/ip/ip.h"
#include "net/pbuf.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "user/include/apos/dev.h"
#include "user/include/apos/vfs/vfs.h"

#define KLOG(lvl, msg, ...) klogfm(KL_NET, lvl, "tuntap: " msg, __VA_ARGS__)

typedef struct {
  nic_t nic;
  apos_dev_t dev_id;
  char_dev_t chardev;
  ssize_t bufsize;
  int flags;

  kspinlock_t lock;
  list_t tx;
  ssize_t tx_queued;

  kthread_queue_t wait;
} tuntap_dev_t;

// NIC operations.
static int tuntap_nic_tx(nic_t* nic, pbuf_t* buf);
static void tuntap_nic_cleanup(nic_t* nic);

static nic_ops_t tuntap_nic_ops = {
  &tuntap_nic_tx,
  &tuntap_nic_cleanup,
};

// Chardev operations.
static int tuntap_cd_read(struct char_dev* dev, void* buf, size_t len,
                          int flags);
static int tuntap_cd_write(struct char_dev* dev, const void* buf, size_t len,
                           int flags);
static int tuntap_cd_poll(struct char_dev* dev, short event_mask,
                          poll_state_t* poll);

nic_t* tuntap_create(ssize_t bufsize, int flags, apos_dev_t* id) {
  if (flags != 0) {
    KLOG(INFO, "unsupported flags 0x%x\n", flags);
    return NULL;
  }

  tuntap_dev_t* tt = KMALLOC(tuntap_dev_t);
  tt->bufsize = bufsize;
  tt->flags = flags;
  tt->lock = KSPINLOCK_NORMAL_INIT;
  tt->tx = LIST_INIT;
  tt->tx_queued = 0;
  kthread_queue_init(&tt->wait);

  // Create the character device first.
  tt->dev_id = kmakedev(DEVICE_MAJOR_TUN, 0);
  tt->chardev.read = &tuntap_cd_read;
  tt->chardev.write = &tuntap_cd_write;
  tt->chardev.poll = &tuntap_cd_poll;
  tt->chardev.dev_data = tt;

  // Initialize the NIC.
  nic_init(&tt->nic);
  tt->nic.type = NIC_TUN;
  kmemset(tt->nic.mac, 0, NIC_MAC_LEN);
  tt->nic.ops = &tuntap_nic_ops;

  // Register the block device and NIC.
  int result = dev_register_char(&tt->chardev, &tt->dev_id);
  if (result) {
    KLOG(WARNING, "unable to create TUN/TAP chardev: %s\n", errorname(-result));
    return NULL;
  }
  *id = tt->dev_id;

  // Initialize the NIC.
  nic_create(&tt->nic, "tun");
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

  // TODO(aoates): redo NIC refcounting and deletion system, this is strange and
  // brittle.
  nic_delete(&tt->nic);
  nic_put(&tt->nic);
  return 0;
}

static int tuntap_nic_tx(nic_t* nic, pbuf_t* buf) {
  KASSERT_DBG(nic->type == NIC_TUN);
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
  kspin_unlock(&tt->lock);
  return 0;
}

static void tuntap_nic_cleanup(nic_t* nic) {
  KASSERT_DBG(nic->type == NIC_TUN);
  tuntap_dev_t* tt = (tuntap_dev_t*)nic;

  while (!list_empty(&tt->tx)) {
    list_link_t* link = list_pop(&tt->tx);
    pbuf_t* pb = container_of(link, pbuf_t, link);
    tt->tx_queued -= pb->total_len;
    pbuf_free(pb);
  }
  KASSERT_DBG(tt->tx_queued == 0);
  kfree(tt);
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
  return -ENOTSUP;
}

static int tuntap_cd_poll(struct char_dev* dev, short event_mask,
                          poll_state_t* poll) {
  return -ENOTSUP;
}
