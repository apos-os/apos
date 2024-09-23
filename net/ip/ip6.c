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
#include "common/kstring.h"
#include "common/refcount.h"
#include "dev/net/nic.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/ip/icmpv6/icmpv6.h"
#include "net/ip/icmpv6/ndp.h"
#include "net/ip/ip6_addr.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/ip6_internal.h"
#include "net/ip/ip6_multicast.h"
#include "net/ip/route.h"
#include "net/link_layer.h"
#include "net/mac.h"
#include "net/pbuf.h"
#include "net/socket/raw.h"
#include "net/socket/tcp/tcp.h"
#include "net/socket/udp.h"
#include "net/util.h"
#include "proc/defint.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

#define ALL_NODES_MULTICAST "ff02::1"
#define LINK_LOCAL_PREFIX "fe80::"

static const nic_ipv6_options_t kDefaultNicOpts = {
    true,  // autoconfigure
    1000,  // dup_detection_timeout_ms
};

void ipv6_init(nic_t* nic) {
  nic->ipv6.opts = kDefaultNicOpts;
  htbl_init(&nic->ipv6.multicast, 10);
  nic->ipv6.iface_id_len = 0;
  kmemset(&nic->ipv6.iface_id, 0, sizeof(struct in6_addr));
  kmemset(&nic->ipv6.gateway, 0, sizeof(nic->ipv6.gateway));
  nic->ipv6.gateway.valid = false;
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

static void addr_dup_timeout_defint(void* arg);
static void addr_dup_timeout(void* arg) {
  nic_addr_t* addr = (nic_addr_t*)arg;
  // TODO(aoates): this technically isn't correct with SMP --- another thread
  // could simultaneously be trying to cancel the timer.  This needs to be fixed
  // in the timer code.
  // TODO(aoates): create a standard utility for this kind of
  // trampoline-to-defint timer so it's not duplicated everywhere.
  kspin_lock_int(&addr->timer_lock);
  addr->timer = TIMER_HANDLE_NONE;
  kspin_unlock_int(&addr->timer_lock);
  defint_schedule(&addr_dup_timeout_defint, arg);
}

static void addr_dup_timeout_defint(void* arg) {
  nic_addr_t* addr = (nic_addr_t*)arg;
  nic_t* nic = addr->nic;

  kspin_lock(&nic->lock);
  if (addr->state != NIC_ADDR_TENTATIVE ||
      addr->a.addr.family != AF_INET6) {
    KLOG(WARNING, "ipv6: nic %s addr %p in unexpected state, can't promote\n",
         nic->name, addr);
    goto done;
  }

  char buf[INET6_PRETTY_LEN];
  KLOG(INFO, "ipv6: configured nic %s with addr %s (confirmed)\n", nic->name,
       inet62str(&addr->a.addr.a.ip6, buf));
  addr->state = NIC_ADDR_ENABLED;

  // If this is a link-local address, send a new router solicitation.
  if (ip6_is_link_local(&addr->a.addr.a.ip6)) {
    ndp_send_router_solicit(nic);
  }

done:
  kspin_unlock(&nic->lock);
  nic_put(nic);
}

void ip6_nic_got_nbr_advert(nic_t* nic, const ip6_hdr_t* ip6_hdr,
                            const ndp_nbr_advert_t* advert) {
  char pretty[INET6_PRETTY_LEN];
  bool unsub = false;
  struct in6_addr unsub_addr;
  kspin_lock(&nic->lock);
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state == NIC_ADDR_TENTATIVE &&
        nic->addrs[i].a.addr.family == AF_INET6 &&
        kmemcmp(&nic->addrs[i].a.addr.a.ip6, &advert->target,
                sizeof(struct in6_addr)) == 0) {
      KLOG(INFO, "ipv6: nic %s detected duplicate for tentative address %s\n",
           nic->name, inet62str(&advert->target, pretty));
      kspin_lock_int(&nic->addrs[i].timer_lock);
      if (nic->addrs[i].timer != TIMER_HANDLE_NONE) {
        cancel_event_timer(nic->addrs[i].timer);
        nic->addrs[i].timer = TIMER_HANDLE_NONE;
        KASSERT(refcount_dec(&nic->ref) != 0);
      }
      kspin_unlock_int(&nic->addrs[i].timer_lock);

      nic->addrs[i].state = NIC_ADDR_CONFLICT;
      unsub = true;
      kmemcpy(&unsub_addr, &advert->target, sizeof(struct in6_addr));
      break;
    }
  }
  kspin_unlock(&nic->lock);

  if (unsub) {
    struct in6_addr solicited_node_addr;
    ip6_solicited_node_addr(&unsub_addr, &solicited_node_addr);
    ip6_multicast_leave(nic, &solicited_node_addr);
  }
}

void ip6_nic_got_dup_solicit(nic_t* nic, nic_addr_t* addr) {
  KASSERT(kspin_is_held(&nic->lock));
  KASSERT_DBG(addr->state == NIC_ADDR_TENTATIVE);
  KASSERT_DBG(addr->a.addr.family == AF_INET6);

  char pretty[INET6_PRETTY_LEN];
  KLOG(INFO, "ipv6: nic %s detected duplicate for tentative address %s\n",
       nic->name, inet62str(&addr->a.addr.a.ip6, pretty));
  kspin_lock_int(&addr->timer_lock);
  if (addr->timer != TIMER_HANDLE_NONE) {
    cancel_event_timer(addr->timer);
    addr->timer = TIMER_HANDLE_NONE;
    KASSERT(refcount_dec(&nic->ref) != 0);
  }
  kspin_unlock_int(&addr->timer_lock);
  addr->state = NIC_ADDR_CONFLICT;
}

int ipv6_configure_addr(nic_t* nic, const network_t* addr) {
  if (addr->addr.family != AF_INET6 || addr->prefix_len < 1 ||
      addr->prefix_len > 128) {
    return -EINVAL;
  }

  char buf[INET6_PRETTY_LEN];
  kspin_lock(&nic->lock);
  int open = -1;
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state != NIC_ADDR_NONE &&
        netaddr_eq(&addr->addr, &nic->addrs[i].a.addr)) {
      kspin_unlock(&nic->lock);
      KLOG(INFO, "ipv6: nic %s already has requested IPv6 address %s\n",
           nic->name, inet62str(&addr->addr.a.ip6, buf));
      return -EEXIST;
    } else if (open < 0 && nic->addrs[i].state == NIC_ADDR_NONE) {
      open = i;
    }
  }

  if (open < 0) {
    KLOG(INFO, "ipv6: can't configure ipv6 on nic %s; no addresses available\n",
         nic->name);
    kspin_unlock(&nic->lock);
    return -ENOMEM;
  }

  nic->addrs[open].state = NIC_ADDR_TENTATIVE;
  nic->addrs[open].a = *addr;

  // Set a timer for confirmation.
  KASSERT_DBG(nic->addrs[open].timer == TIMER_HANDLE_NONE);
  refcount_inc(&nic->ref);

  kspin_lock_int(&nic->addrs[open].timer_lock);
  apos_ms_t end = get_time_ms() +
      nic->ipv6.opts.dup_detection_timeout_ms;
  if (register_event_timer(end, &addr_dup_timeout, &nic->addrs[open],
                           &nic->addrs[open].timer) != 0) {
    KLOG(WARNING,
         "ipv6: unable to register timer for duplicate address detection "
         "expiration\n");
  }
  kspin_unlock_int(&nic->addrs[open].timer_lock);
  kspin_unlock(&nic->lock);

  KLOG(INFO, "ipv6: configured nic %s with addr %s (tentative)\n", nic->name,
       inet62str(&addr->addr.a.ip6, buf));

  // Join the solicited-node multicast address.
  struct in6_addr solicited_node_addr;
  ip6_solicited_node_addr(&addr->addr.a.ip6, &solicited_node_addr);
  ip6_multicast_join(nic, &solicited_node_addr);

  // Send a neighbor solicitation for the address.
  kspin_lock(&nic->lock);
  ndp_send_request(nic, &addr->addr.a.ip6, true);
  kspin_unlock(&nic->lock);

  return 0;
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

  // Generate the interface ID.
  nic->ipv6.iface_id_len = 64;
  nic->ipv6.iface_id.s6_addr[8] = nic->mac.addr[0];
  nic->ipv6.iface_id.s6_addr[8] ^= 0x2;  // Flip the local/global bit.
  nic->ipv6.iface_id.s6_addr[9] = nic->mac.addr[1];
  nic->ipv6.iface_id.s6_addr[10] = nic->mac.addr[2];
  nic->ipv6.iface_id.s6_addr[11] = 0xff;
  nic->ipv6.iface_id.s6_addr[12] = 0xfe;
  nic->ipv6.iface_id.s6_addr[13] = nic->mac.addr[3];
  nic->ipv6.iface_id.s6_addr[14] = nic->mac.addr[4];
  nic->ipv6.iface_id.s6_addr[15] = nic->mac.addr[5];
  kspin_unlock(&nic->lock);

  if (!opts->autoconfigure) {
    return;
  }

  // Start by generating a link-local address for the interface.
  network_t link_local;
  link_local.addr.family = AF_INET6;
  KASSERT(0 == str2inet6(LINK_LOCAL_PREFIX, &link_local.addr.a.ip6));
  ip6_addr_merge(&link_local.addr.a.ip6, &nic->ipv6.iface_id,
                 128 - nic->ipv6.iface_id_len);
  link_local.prefix_len = 64;

  if (ipv6_configure_addr(nic, &link_local) != 0) {
    KLOG(WARNING, "ipv6: unable to configure link-local address on NIC %s\n",
         nic->name);
  }
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
