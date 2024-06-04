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
#include "net/ip/ip6.h"

#include "common/kassert.h"
#include "common/klog.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/ip/icmpv6/icmpv6.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/route.h"
#include "net/link_layer.h"
#include "net/socket/raw.h"
#include "net/socket/udp.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

#define LINK_LOCAL_PREFIX "fe80::"

void ipv6_enable(nic_t* nic) {
  // Start by generating a link-local address for the interface.
  // TODO(ipv6): do this properly randomly.
  struct in6_addr link_local;
  KASSERT(0 == str2inet6(LINK_LOCAL_PREFIX, &link_local));
  link_local.s6_addr[15] = 1;

  kspin_lock(&nic->lock);
  int open = -1;
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state != NIC_ADDR_NONE &&
        nic->addrs[i].a.addr.family == ADDR_INET6) {
      KLOG(INFO, "ipv6: nic %s already has IPv6 address\n", nic->name);
      kspin_unlock(&nic->lock);
      return;
    } else if (open < 0 && nic->addrs[i].state == NIC_ADDR_NONE) {
      open = i;
    }
  }

  if (open < 0) {
    KLOG(INFO, "ipv6: can't configure ipv6 on nic %s; no addresses available\n",
         nic->name);
    kspin_unlock(&nic->lock);
    return;
  }

  nic->addrs[open].state = NIC_ADDR_ENABLED;
  nic->addrs[open].a.addr.a.ip6 = link_local;
  nic->addrs[open].a.addr.family = ADDR_INET6;
  nic->addrs[open].a.prefix_len = 64;
  kspin_unlock(&nic->lock);

  char buf[INET6_PRETTY_LEN];
  KLOG(INFO, "ipv6: configured nic %s with addr %s\n", nic->name,
       inet62str(&link_local, buf));
  // TODO(ipv6): subscribe to multicast groups
  // TODO(ipv6): kick off SLAAC.
}

int ip6_send(pbuf_t* pb, bool allow_block) {
  char addrbuf[INET6_PRETTY_LEN];
  if (pbuf_size(pb) < sizeof(ip6_hdr_t)) {
    KLOG(INFO, "net: rejecting too-short IPv6 packet\n");
    pbuf_free(pb);
    return -EINVAL;
  }

  ip6_hdr_t* hdr = (ip6_hdr_t*)pbuf_get(pb);
  if (ip6_version(*hdr) != 6) {
    KLOG(INFO, "net: rejecting IPv6 packet with bad version %d\n",
         ip6_version(*hdr));
    pbuf_free(pb);
    return -EINVAL;
  }

  netaddr_t dst;
  dst.family = AF_INET6;
  dst.a.ip6 = hdr->dst_addr;
  ip_routed_t route;
  if (ip_route(dst, &route) == false) {
    KLOG(INFO, "net: unable to route packet to %s\n",
         inet62str(&hdr->dst_addr, addrbuf));
    pbuf_free(pb);
    return -ENETUNREACH;
  }

  // Check the source address --- for non-RAW sockets, we should not have been
  // allowed to bind() a socket to this source IP if it wasn't valid.
  netaddr_t src;
  src.family = AF_INET6;
  src.a.ip6 = hdr->src_addr;
  if (inet_source_valid(&src, route.nic) != 0) {
    KLOG(INFO, "net: unable to route packet with src %s on iface %s\n",
         inet62str(&hdr->src_addr, addrbuf), route.nic->name);
    nic_put(route.nic);
    pbuf_free(pb);
    return -EADDRNOTAVAIL;
  }

  int result =
      net_link_send(route.nic, route.nexthop, pb, ET_IPV6, allow_block);
  nic_put(route.nic);
  if (result != 0) {
    pbuf_free(pb);
  }
  return result;
}

static bool validate_hdr_v6(const pbuf_t* pb) {
  if (pbuf_size(pb) < sizeof(ip6_hdr_t)) {
    KLOG(DEBUG, "net: truncated IPv6 packet\n");
    return false;
  }
  const ip6_hdr_t* hdr = (const ip6_hdr_t*)pbuf_getc(pb);
  if (ip6_version(*hdr) != 6) {
    KLOG(DEBUG, "net: IPv6 packet with bad version %d\n", ip6_version(*hdr));
    return false;
  }
  const size_t payload_len = btoh16(hdr->payload_len);
  if (payload_len > pbuf_size(pb) - sizeof(ip6_hdr_t)) {
    KLOG(DEBUG, "net: IPv6 packet with bad length %zu\n", payload_len);
    return false;
  }
  return true;
}

void ip6_recv(nic_t* nic, pbuf_t* pb) {
  // Verify the packet.
  if (!validate_hdr_v6(pb)) {
    KLOG(INFO, "net: dropping invalid IPv6 packet\n");
    // TODO(aoates): increment stats.
    pbuf_free(pb);
    return;
  }

  const ip6_hdr_t* hdr = (const ip6_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(ip6_version(*hdr) == 6);
  char buf1[INET6_PRETTY_LEN], buf2[INET6_PRETTY_LEN];
  KLOG(DEBUG2, "ipv6 rx(%s): %s -> %s, next_hdr=%d\n", nic->name,
       inet62str(&hdr->src_addr, buf1), inet62str(&hdr->dst_addr, buf2),
       hdr->next_hdr);

  // TODO(ipv6): handle additional IPv6 packet headers.
  size_t header_len = sizeof(ip6_hdr_t);
  bool handled = false;
  if (hdr->next_hdr == IPPROTO_ICMPV6) {
    handled = icmpv6_recv(nic, hdr, header_len, pb);
  } else if (hdr->next_hdr == IPPROTO_UDP) {
    handled = sock_udp_dispatch(pb, ET_IPV6, hdr->next_hdr, header_len);
  }
  // TODO(ipv6): handle TCP sockets.

  // pb is now a dangling pointer unless handled is false!
  if (!handled) {
    struct sockaddr_in6 src_addr;
    src_addr.sin6_family = AF_INET;
    src_addr.sin6_addr = hdr->src_addr;
    src_addr.sin6_port = 0;
    sock_raw_dispatch(pb, ET_IPV6, hdr->next_hdr, (struct sockaddr*)&src_addr,
                      sizeof(src_addr));
    pbuf_free(pb);
  }
}
