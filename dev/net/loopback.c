// Copyright 2018 Andrew Oates.  All Rights Reserved.
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

#include "dev/net/loopback.h"

#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/link_layer.h"
#include "net/pbuf.h"
#include "proc/defint.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

// Parameters that control the maximum throughput of the loopback device.  Each
// defint run will only process at most this many packets; if the queue is not
// exhausted, then another run will be scheduled after LOOPBACK_REDEFINT_DELAY
// ms.  This prevents the loopback defint loop from starving all other system
// work (which can itself cause a positive feedback loop with e.g. TCP
// retransmits feeding back into the starvation).
#define LOOPBACK_MAX_PACKETS 50
#define LOOPBACK_REDEFINT_DELAY 100

typedef struct {
  nic_t public;
  list_t queue;
  bool processing;  // Set to true when there is a defint processing packets.
} loopback_nic_t;

static void dispatch_link_local(void* arg);
static void dispatch_link_local_timer(void* arg) {
  defint_schedule(&dispatch_link_local, arg);
}

static void dispatch_link_local(void* arg) {
  loopback_nic_t* nic = (loopback_nic_t*)arg;
  int num_packets = 0;
  while (num_packets < LOOPBACK_MAX_PACKETS) {
    kspin_lock(&nic->public.lock);
    nic->processing = true;
    if (list_empty(&nic->queue)) {
      nic->processing = false;
      kspin_unlock(&nic->public.lock);
      nic_put(&nic->public);
      return;
    }

    list_link_t* link = list_pop(&nic->queue);
    kspin_unlock(&nic->public.lock);

    pbuf_t* pb = container_of(link, pbuf_t, link);
    ethertype_t protocol = *(ethertype_t*)pbuf_getc(pb);
    pbuf_pop_header(pb, sizeof(ethertype_t));

    net_link_recv(&nic->public, pb, protocol);
    num_packets++;
  }

  // Schedule another to do more work.
  if (register_event_timer(get_time_ms() + LOOPBACK_REDEFINT_DELAY,
                           &dispatch_link_local_timer, nic, NULL) != 0) {
    KLOG(WARNING, "Unable to schedule link-local dispatch timer\n");
  }
}

void loopback_send(nic_t* public, pbuf_t* pb, ethertype_t protocol) {
  KASSERT(public->type == NIC_LOOPBACK);
  loopback_nic_t* nic = (loopback_nic_t*)public;

  // Stash the protocol in the space at the top of the packet.
  pbuf_push_header(pb, sizeof(ethertype_t));
  *(ethertype_t*)pbuf_get(pb) = protocol;

  kspin_lock(&nic->public.lock);
  if (!nic->processing && list_empty(&nic->queue)) {
    nic_ref(&nic->public);
    defint_schedule(&dispatch_link_local, nic);
  }
  list_push(&nic->queue, &pb->link);
  kspin_unlock(&nic->public.lock);
}

static void loopback_cleanup(nic_t* public) {
  KASSERT(public->type == NIC_LOOPBACK);
  loopback_nic_t* nic = (loopback_nic_t*)public;

  kspin_lock(&nic->public.lock);
  while (!list_empty(&nic->queue)) {
    list_link_t* link = list_pop(&nic->queue);
    pbuf_t* pb = container_of(link, pbuf_t, link);
    pbuf_free(pb);
  }
  kspin_unlock(&nic->public.lock);
}

static nic_ops_t kLoopbackNicOps = {
  .nic_cleanup = loopback_cleanup,
};

// TODO(aoates): consider rewriting loopback NIC's to sit underneath ethernet
// layer, rather than intercepting above it.
nic_t* loopback_create(void) {
  loopback_nic_t* nic = KMALLOC(loopback_nic_t);
  nic_init(&nic->public);
  nic->public.type = NIC_LOOPBACK;
  kmemset(&nic->public.mac.addr, 0, NIC_MAC_LEN);
  nic->public.ops = &kLoopbackNicOps;
  nic->queue = LIST_INIT;
  nic->processing = false;
  nic_create(&nic->public, "lo");
  KLOG(INFO, "net: created loopback device %s\n", nic->public.name);
  return &nic->public;
}
