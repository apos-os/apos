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
#include "net/ip/icmpv6/ndp.h"

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "net/eth/eth.h"
#include "net/eth/mac.h"
#include "net/ip/checksum.h"
#include "net/ip/icmpv6/ndp_protocol.h"
#include "net/ip/ip6_hdr.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "net/util.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

void ndp_rx(nic_t* nic, pbuf_t* pb) {
}

// TODO(aoates): refactor the code so that this (and arp_send_request) can be
// called without the NIC lock held.
void ndp_send_request(nic_t* nic, const struct in6_addr* addr) {
  KASSERT_DBG(kspin_is_held(&nic->lock));
  // First calculate the IPv6 solicited-node multicast address.
  struct in6_addr dst_addr;
  KASSERT(str2inet6("ff02:0:0:0:0:1:ff00::", &dst_addr) == 0);
  dst_addr.s6_addr[13] = addr->s6_addr[13];
  dst_addr.s6_addr[14] = addr->s6_addr[14];
  dst_addr.s6_addr[15] = addr->s6_addr[15];

  // Create the request packet.
  size_t pkt_size = sizeof(ndp_nbr_solict_t) + 8;
  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE, pkt_size);
  if (!pb) {
    KLOG(DFATAL, "IPv6 NDP: unable to allocate packet\n");
    return;
  }

  // Fill in the ICMPv6 header.
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 0;
  kmemcpy(&pkt->target, addr, sizeof(struct in6_addr));

  // Add a source link-layer address option.
  uint8_t* option = ((uint8_t*)pkt + sizeof(ndp_nbr_solict_t));
  option[0] = ICMPV6_OPTION_SRC_LL_ADDR;
  option[1] = 1;  // 8 octets.
  _Static_assert(NIC_MAC_LEN == 6, "Mismatched NIC_MAC_LEN");
  kmemcpy(&option[2], &nic->mac.addr, NIC_MAC_LEN);

  // Find the IPv6 address to send from.
  struct in6_addr src_addr;
  bool found = 0;
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].addr.family == AF_INET6) {
      found = true;
      kmemcpy(&src_addr, &nic->addrs[i].addr.a.ip6, sizeof(struct in6_addr));
      break;
    }
  }
  if (!found) {
    KLOG(INFO,
         "IPv6 NDP: cannot send NDP on iface %s, no IPv6 address configured\n",
         nic->name);
    return;
  }

  // Calculate the checksum.
  ip6_pseudo_hdr_t ip6_phdr;
  kmemcpy(&ip6_phdr.src_addr, &src_addr, sizeof(src_addr));
  kmemcpy(&ip6_phdr.dst_addr, &dst_addr, sizeof(dst_addr));
  ip6_phdr.payload_len = htob32(pkt_size);
  kmemset(&ip6_phdr._zeroes, 0, 3);
  ip6_phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&ip6_phdr, sizeof(ip6_phdr), pbuf_get(pb), pkt_size);

  // Add the IPv6 and Ethernet headers and send.
  ip6_add_hdr(pb, &src_addr, &dst_addr, IPPROTO_ICMPV6, /* flow label */ 0);

  // Override hop limit, which must be 255.
  ip6_hdr_t* ip6_hdr = (ip6_hdr_t*)pbuf_get(pb);
  ip6_hdr->hop_limit = 255;

  nic_mac_t eth_dst;
  ip6_multicast_mac(&dst_addr, eth_dst.addr);
  eth_add_hdr(pb, &eth_dst, &nic->mac, ET_IPV6);
  int result = eth_send_raw(nic, pb);
  if (result) {
    KLOG(WARNING, "IPv6 NDP: unable to send NDP packet: %s\n",
         errorname(-result));
  }
}
