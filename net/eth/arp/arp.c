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

#include "arch/common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "net/eth/eth.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

// ARP packet format (assuming ethernet and ipv4).  Everything in
// network-byte-order.
typedef struct __attribute__((packed)) {
  uint16_t htype;  // Hardware type
  uint16_t ptype;  // Protocol type
  uint8_t hlen;    // Hardware address length
  uint8_t plen;    // Protocol address length
  uint16_t oper;   // Operation
  uint8_t sha[6];  // Sender hardware address
  uint8_t spa[4];  // Sender protocol address
  uint8_t tha[6];  // Target hardware address
  uint8_t tpa[4];  // Target protocol address
} arp_packet_t;

typedef enum {
  ARP_HTYPE_ETH = 1,
} arp_htype_t;

typedef enum {
  ARP_OPER_REQUEST = 1,
  ARP_OPER_REPLY = 2,
} arp_oper_t;

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
  for (int addr_idx = 0; addr_idx < NIC_MAX_ADDRS; ++addr_idx) {
    if (nic->addrs[addr_idx].sa_family == AF_INET) {
      const struct sockaddr_in* addr =
          (const struct sockaddr_in*)&nic->addrs[addr_idx];
      if (addr->sin_addr.s_addr == target_addr) {
        KLOG(DEBUG, "ARP: found NIC %s with matching IP\n", nic->name);

        pbuf_t* reply_buf = arp_mkpacket(ARP_OPER_REPLY);
        arp_packet_t* reply = (arp_packet_t*)pbuf_get(reply_buf);
        kmemcpy(&reply->sha, nic->mac, ETH_MAC_LEN);
        kmemcpy(&reply->spa, &target_addr, sizeof(target_addr));
        kmemcpy(&reply->tha, packet->sha, ETH_MAC_LEN);
        kmemcpy(&reply->tpa, packet->spa, sizeof(in_addr_t));

        eth_add_hdr(reply_buf, packet->sha, nic->mac, ET_ARP);
        int result = nic->ops->nic_tx(nic, reply_buf);
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

    case ARP_OPER_REPLY:
      // TODO(aoates): handle replies and gratuitous ARP.
      break;

    default:
      KLOG(INFO, "ARP: dropping packet with invalid operation: %d\n",
           packet.oper);
      break;
  }

  pbuf_free(pb);
}
