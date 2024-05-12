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

#include "net/eth/arp/arp.h"

#include <stdint.h>

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "net/eth/arp/arp_packet.h"
#include "net/eth/eth.h"
#include "net/neighbor_cache_ops.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

_Static_assert(sizeof(arp_packet_t) == 28, "bad arp_packet_t size");

pbuf_t* arp_mkpacket(arp_oper_t oper) {
  pbuf_t* pb = pbuf_create(sizeof(eth_hdr_t), sizeof(arp_packet_t));
  arp_packet_t* hdr = (arp_packet_t*)pbuf_get(pb);
  hdr->htype = htob16(ARP_HTYPE_ETH);
  hdr->ptype = htob16(ET_IPV4);
  hdr->hlen = ETH_MAC_LEN;
  hdr->plen = sizeof(in_addr_t);
  hdr->oper = htob16(oper);
  return pb;
}

static void arp_handle_request(nic_t* nic, const arp_packet_t* packet) {
  KASSERT(nic->type == NIC_ETHERNET);

  // TODO(aoates): should we learn a MAC apping from the (SHA, SPA) pair in the
  // request packet?

  // See if the NIC the request came in on has a matching IP address.
  in_addr_t target_addr;
  kmemcpy(&target_addr, packet->tpa, sizeof(in_addr_t));
  char inetbuf[INET_PRETTY_LEN];
  KLOG(DEBUG2, "ARP: got request for IP %s on %s\n",
       inet2str(target_addr, inetbuf), nic->name);

  kspin_lock(&nic->lock);
  for (int addr_idx = 0; addr_idx < NIC_MAX_ADDRS; ++addr_idx) {
    if (nic->addrs[addr_idx].a.addr.family == AF_INET) {
      KASSERT(nic->addrs[addr_idx].state == NIC_ADDR_ENABLED);
      if (nic->addrs[addr_idx].a.addr.a.ip4.s_addr == target_addr) {
        kspin_unlock(&nic->lock);
        KLOG(DEBUG, "ARP: found NIC %s with matching IP (%s)\n", nic->name,
             inet2str(target_addr, inetbuf));

        pbuf_t* reply_buf = arp_mkpacket(ARP_OPER_REPLY);
        arp_packet_t* reply = (arp_packet_t*)pbuf_get(reply_buf);
        kmemcpy(&reply->sha, &nic->mac.addr, ETH_MAC_LEN);
        kmemcpy(&reply->spa, &target_addr, sizeof(target_addr));
        kmemcpy(&reply->tha, packet->sha, ETH_MAC_LEN);
        kmemcpy(&reply->tpa, packet->spa, sizeof(in_addr_t));

        eth_add_hdr(reply_buf, raw2mac(packet->sha), &nic->mac, ET_ARP);
        int result = eth_send_raw(nic, reply_buf);
        if (result) {
          KLOG(INFO, "ARP: unable to send reply on %s: %s\n",
               nic->name, errorname(-result));
          pbuf_free(reply_buf);
        }

        // Our job is done.
        return;
      }
    }
  }
  kspin_unlock(&nic->lock);
}

static void arp_handle_reply(nic_t* nic, const arp_packet_t* packet) {
  KASSERT(nic->type == NIC_ETHERNET);

  // TODO(aoates): verify that the source addresses are valid (i.e. aren't
  // broadcast or multicast addresses, etc).
  netaddr_t src_addr;
  src_addr.family = AF_INET;
  kmemcpy(&src_addr.a.ip4, packet->spa, sizeof(packet->spa));
  nbr_cache_insert(nic, src_addr, packet->sha);
}

void arp_rx(nic_t* nic, pbuf_t* pb) {
  if (pbuf_size(pb) < sizeof(arp_packet_t)) {
    KLOG(INFO, "ARP: dropping packet with bad size %zu\n", pbuf_size(pb));
    pbuf_free(pb);
    return;
  }

  arp_packet_t packet;
  kmemcpy(&packet, pbuf_get(pb), sizeof(arp_packet_t));
  packet.htype = btoh16(packet.htype);
  packet.ptype = btoh16(packet.ptype);
  packet.oper = btoh16(packet.oper);
  if (packet.htype != ARP_HTYPE_ETH || packet.ptype != ET_IPV4 ||
      packet.hlen != 6 || packet.plen != 4) {
    KLOG(INFO, "ARP: dropping packet with invalid {h,p}{type,len}\n");
    pbuf_free(pb);
    return;
  }

  switch (packet.oper) {
    case ARP_OPER_REQUEST:
      arp_handle_request(nic, &packet);
      break;

    case ARP_OPER_REPLY:
      arp_handle_reply(nic, &packet);
      break;

    default:
      KLOG(INFO, "ARP: dropping packet with invalid operation: %d\n",
           packet.oper);
      break;
  }

  pbuf_free(pb);
}

void arp_send_request(nic_t* nic, in_addr_t addr) {
  KASSERT_DBG(kspin_is_held(&nic->lock));
  char inetbuf[INET_PRETTY_LEN];
  KLOG(DEBUG, "ARP: sending request for %s on %s\n", inet2str(addr, inetbuf),
       nic->name);

  in_addr_t nic_addr = 0;
  // TODO(aoates): consider some NIC helper functions to find particular
  // addresses, or an address of a particular family.
  for (int addr_idx = 0; addr_idx < NIC_MAX_ADDRS; ++addr_idx) {
    if (nic->addrs[addr_idx].a.addr.family == AF_INET) {
      nic_addr = nic->addrs[addr_idx].a.addr.a.ip4.s_addr;
      break;
    }
  }
  if (nic_addr == 0) {
    KLOG(INFO,
         "ARP: unable to request request on NIC %s, which doesn't have an IPv4 "
         "address configured",
         nic->name);
    return;  // TODO(aoates): signal error up the stack?
  }

  pbuf_t* request_buf = arp_mkpacket(ARP_OPER_REQUEST);
  arp_packet_t* req = (arp_packet_t*)pbuf_get(request_buf);
  kmemcpy(&req->sha, &nic->mac.addr, ETH_MAC_LEN);
  kmemcpy(&req->spa, &nic_addr, sizeof(nic_addr));
  eth_mkbroadcast(req->tha);
  kmemcpy(&req->tpa, &addr, sizeof(addr));
  eth_add_hdr(request_buf, raw2mac(req->tha), &nic->mac, ET_ARP);
  int result = eth_send_raw(nic, request_buf);
  if (result) {
    KLOG(INFO, "ARP: unable to send request on %s: %s\n", nic->name,
         errorname(-result));
    pbuf_free(request_buf);
  }
}
