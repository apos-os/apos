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

#include "net/link_layer.h"

#include "common/errno.h"
#include "common/klog.h"
#include "net/eth/arp/arp.h"
#include "net/eth/eth.h"
#include "net/ip/ip.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

int net_link_send(nic_t* nic, netaddr_t next_hop, pbuf_t* pb,
                  ethertype_t protocol, bool allow_block) {
  switch (nic->type) {
    case NIC_ETHERNET:
      return eth_send(nic, next_hop, pb, protocol, allow_block);

    case NIC_LOOPBACK:
      net_link_recv(nic, pb, protocol);
      return 0;

    case NIC_TUN:
      return nic->ops->nic_tx(nic, pb);

    case NIC_UNKNOWN:
      break;
  }

  KLOG(DFATAL, "Dropping packet for unknown NIC type\n");
  return -EINVAL;
}

void net_link_recv(nic_t* nic, pbuf_t* pb, ethertype_t protocol) {
  switch (protocol) {
    case ET_IPV4:
      ip_recv(nic, pb);
      return;

    case ET_ARP:
      arp_rx(nic, pb);
      return;
  }

  KLOG(INFO, "rx(%s): dropping packet with unknown ethertype %#06x\n",
       nic->name, protocol);
  pbuf_free(pb);
}
