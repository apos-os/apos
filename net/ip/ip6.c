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
#include "dev/net/nic.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/ip/icmpv6/icmpv6.h"
#include "net/ip/ip6_addr.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/ip6_multicast.h"
#include "net/ip/route.h"
#include "net/link_layer.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "net/socket/raw.h"
#include "net/socket/tcp/tcp.h"
#include "net/socket/udp.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

#define ALL_NODES_MULTICAST "ff02::1"
#define LINK_LOCAL_PREFIX "fe80::"

static const nic_ipv6_options_t kDefaultNicOpts = {
  true, // autoconfigure
};

void ipv6_init(nic_t* nic) {
  htbl_init(&nic->ipv6.multicast, 10);
}

static void do_delete(void* arg, uint32_t key, void* val) {
  kfree(val);
}

void ipv6_cleanup(nic_t* nic) {
  htbl_clear(&nic->ipv6.multicast, &do_delete, NULL);
  htbl_cleanup(&nic->ipv6.multicast);
}

const nic_ipv6_options_t* ipv6_default_nic_opts(void) {
  return &kDefaultNicOpts;
}

void ipv6_enable(nic_t* nic, const nic_ipv6_options_t* opts) {
  // Subscribe to the all-nodes multicast address on the NIC (bypassing IPv6
  // multicast logic).
  struct in6_addr all_nodes;
  KASSERT(0 == str2inet6(ALL_NODES_MULTICAST, &all_nodes));
  nic_mac_t all_nodes_mac;
  ip6_multicast_mac(&all_nodes, all_nodes_mac.addr);
  nic->ops->nic_mc_sub(nic, &all_nodes_mac);

  kspin_lock(&nic->lock);
  nic->ipv6.opts = *opts;
  kspin_unlock(&nic->lock);

  if (!opts->autoconfigure) {
    return;
  }

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

  // Join the solicited-node multicast address.
  struct in6_addr solicited_node_addr;
  ip6_solicited_node_addr(&link_local, &solicited_node_addr);
  ip6_multicast_join(nic, &solicited_node_addr);

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

  // Trim off any extra bytes at the end of the packet.
  if (btoh16(hdr->payload_len) + sizeof(ip6_hdr_t) < pbuf_size(pb)) {
    pbuf_trim_end(pb,
                  pbuf_size(pb) - btoh16(hdr->payload_len) - sizeof(ip6_hdr_t));
  }

  // TODO(ipv6): handle additional IPv6 packet headers.
  size_t header_len = sizeof(ip6_hdr_t);
  bool handled = false;
  if (hdr->next_hdr == IPPROTO_ICMPV6) {
    handled = icmpv6_recv(nic, hdr, header_len, pb);
  } else if (hdr->next_hdr == IPPROTO_UDP) {
    handled = sock_udp_dispatch(pb, ET_IPV6, hdr->next_hdr, header_len);
  } else if (hdr->next_hdr == IPPROTO_TCP) {
    handled = sock_tcp_dispatch(pb, ET_IPV6, hdr->next_hdr, header_len);
  }

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
