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
#include "net/addr.h"
#include "net/eth/eth.h"
#include "net/eth/mac.h"
#include "net/ip/checksum.h"
#include "net/ip/icmpv6/ndp_internal.h"
#include "net/ip/icmpv6/ndp_protocol.h"
#include "net/ip/icmpv6/protocol.h"
#include "net/ip/ip6.h"
#include "net/ip/ip6_addr.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/ip6_internal.h"
#include "net/ip/util.h"
#include "net/mac.h"
#include "net/neighbor_cache_ops.h"
#include "net/pbuf.h"
#include "net/util.h"
#include "proc/spinlock.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

int ndp_parse_opts(const uint8_t* buf, size_t len, const ndp_option_t** opts,
                   int max_opts) {
  for (int i = 0; i < max_opts; ++i) {
    opts[i] = NULL;
  }
  int count = 0;
  while (len >= 8) {
    uint8_t optlen = buf[1] * 8;
    if (optlen > len) {
      KLOG(DEBUG, "ICMPv6: invalid NDP option (too long)\n");
      return -EINVAL;
    } else if (optlen == 0) {
      KLOG(DEBUG, "ICMPv6: invalid NDP option (length zero)\n");
      return -EINVAL;
    }

    if (count < max_opts) {
      opts[count] = (const ndp_option_t*)buf;
    }
    count++;
    buf += optlen;
    len -= optlen;
  }
  if (len != 0) {
    KLOG(DEBUG, "ICMPv6: invalid NDP option (too short)\n");
    return -EINVAL;
  }
  return count;
}

// Creates a solicit or advert packet.  NIC must be locked.  Returns it up
// through the IPv6 header (not including the link-layer header).
static pbuf_t* ndp_mkpkt(nic_t* nic, bool src_any_addr,
                         const struct in6_addr* dst_addr, int type,
                         const struct in6_addr* pkt_addr, uint32_t flags,
                         int option_type, const uint8_t* option_val) {
  _Static_assert(sizeof(ndp_nbr_advert_t) == sizeof(ndp_nbr_solict_t),
                 "Bad packet sizes");
  KASSERT_DBG(kspin_is_held(&nic->lock));

  bool include_src_opt = !src_any_addr;
  size_t pkt_size = sizeof(ndp_nbr_advert_t) + (include_src_opt ? 8 : 0);
  if (!pkt_addr) {
    pkt_size -= sizeof(struct in6_addr);
  }
  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE, pkt_size);
  if (!pb) {
    KLOG(DFATAL, "IPv6 NDP: unable to allocate packet\n");
    return NULL;
  }

  // Fill in the ICMPv6 header.
  ndp_nbr_advert_t* pkt = (ndp_nbr_advert_t*)pbuf_get(pb);
  pkt->hdr.type = type;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->flags = htob32(flags);
  if (pkt_addr) {
    kmemcpy(&pkt->target, pkt_addr, sizeof(struct in6_addr));
  }

  // Add a source link-layer address option.
  if (include_src_opt) {
    uint8_t* option = ((uint8_t*)pkt + (pkt_size - 8));
    option[0] = option_type;
    option[1] = 1;  // 8 octets.
    _Static_assert(NIC_MAC_LEN == 6, "Mismatched NIC_MAC_LEN");
    kmemcpy(&option[2], option_val, NIC_MAC_LEN);
  }

  // Find the IPv6 address to send from.
  netaddr_t net_dst_addr, src_addr;
  src_addr.family = AF_INET6;
  net_dst_addr.family = AF_INET6;
  kmemcpy(&net_dst_addr.a.ip6, dst_addr, sizeof(struct in6_addr));
  if (src_any_addr) {
    kmemset(&src_addr.a.ip6, 0, sizeof(struct in6_addr));
  } else {
    if (ip6_pick_nic_src_locked(&net_dst_addr, nic, &src_addr) != 0) {
      KLOG(INFO,
           "IPv6 NDP: cannot send NDP on iface %s, no IPv6 address configured\n",
           nic->name);
      pbuf_free(pb);
      return NULL;
    }
  }

  // Calculate the checksum.
  ip6_pseudo_hdr_t ip6_phdr;
  kmemcpy(&ip6_phdr.src_addr, &src_addr.a.ip6, sizeof(struct in6_addr));
  kmemcpy(&ip6_phdr.dst_addr, dst_addr, sizeof(struct in6_addr));
  ip6_phdr.payload_len = htob32(pkt_size);
  kmemset(&ip6_phdr._zeroes, 0, 3);
  ip6_phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&ip6_phdr, sizeof(ip6_phdr), pbuf_get(pb), pkt_size);

  // Add the IPv6 and Ethernet headers and send.
  ip6_add_hdr(pb, &src_addr.a.ip6, dst_addr, IPPROTO_ICMPV6,
              /* flow label */ 0);

  // Override hop limit, which must be 255.
  ip6_hdr_t* ip6_hdr = (ip6_hdr_t*)pbuf_get(pb);
  ip6_hdr->hop_limit = 255;

  return pb;
}

static void handle_advert(nic_t* nic, const ip6_hdr_t* ip6_hdr, pbuf_t* pb) {
  const ndp_nbr_advert_t* hdr = (const ndp_nbr_advert_t*)pbuf_getc(pb);
  KASSERT(hdr->hdr.type == ICMPV6_NDP_NBR_ADVERT);
  if (hdr->hdr.code != 0) {
    KLOG(INFO, "ICMPv6 NDP: NDP packet with non-zero code, dropping\n");
    return;
  }
  if (pbuf_size(pb) < sizeof(ndp_nbr_advert_t)) {
    KLOG(INFO, "ICMPv6 NDP: NDP packet too short, dropping\n");
    return;
  }
  // TODO(ipv6): handle the override flag.

  const int kMaxOpts = 10;
  const ndp_option_t* opts[kMaxOpts];
  size_t opts_offset = sizeof(ndp_nbr_advert_t);
  int num_opts = ndp_parse_opts(pbuf_get(pb) + opts_offset,
                                pbuf_size(pb) - opts_offset, opts, kMaxOpts);
  if (num_opts < 0) {
    KLOG(INFO, "ICMPv6: NDP bad options; dropping\n");
    return;
  }

  uint8_t ll_tgt[ETH_MAC_LEN];
  bool found = false;
  for (int i = 0; i < num_opts; ++i) {
    if (opts[i]->type == ICMPV6_OPTION_TGT_LL_ADDR) {
      if (opts[i]->len != 1) {
        KLOG(INFO, "ICMPv6 NDP: bad LL target option size\n");
        return;
      }

      kmemcpy(&ll_tgt, opts[i]->value, ETH_MAC_LEN);
      found = true;
      break;
    }
  }
  if (!found) {
    KLOG(INFO, "ICMPv6 NDP: no LL target option, ignoring\n");
    return;
  }

  netaddr_t addr;
  addr.family = AF_INET6;
  kmemcpy(&addr.a.ip6, &hdr->target, sizeof(struct in6_addr));
  nbr_cache_insert(nic, addr, ll_tgt);

  ip6_nic_got_nbr_advert(nic, ip6_hdr, hdr);
}

static void handle_solicit(nic_t* nic, const ip6_hdr_t* ip_hdr, pbuf_t* pb) {
  const ndp_nbr_solict_t* hdr = (const ndp_nbr_solict_t*)pbuf_getc(pb);
  KASSERT(hdr->hdr.type == ICMPV6_NDP_NBR_SOLICIT);
  if (hdr->hdr.code != 0) {
    KLOG(INFO, "ICMPv6 NDP: NDP packet with non-zero code, dropping\n");
    return;
  }
  if (pbuf_size(pb) < sizeof(ndp_nbr_solict_t)) {
    KLOG(INFO, "ICMPv6 NDP: NDP packet too short, dropping\n");
    return;
  }

  // Check if this request matches any of our IP addresses.
  char addrbuf[INET6_PRETTY_LEN];
  KLOG(DEBUG2, "IPv6 NDP: got request for IP %s on %s\n",
       inet62str(&hdr->target, addrbuf), nic->name);

  // First look for the source link-layer option (but don't insert yet).
  const int kMaxOpts = 10;
  const ndp_option_t* opts[kMaxOpts];
  size_t opts_offset = sizeof(ndp_nbr_solict_t);
  int num_opts = ndp_parse_opts(pbuf_get(pb) + opts_offset,
                                pbuf_size(pb) - opts_offset, opts, kMaxOpts);
  if (num_opts < 0) {
    KLOG(INFO, "ICMPv6: NDP bad options; dropping\n");
    return;
  }

  uint8_t ll_src[ETH_MAC_LEN];
  bool ll_src_found = false;
  for (int i = 0; i < num_opts; ++i) {
    if (opts[i]->type == ICMPV6_OPTION_SRC_LL_ADDR) {
      if (opts[i]->len != 1) {
        KLOG(INFO, "ICMPv6 NDP: bad LL source option size\n");
        return;
      }

      kmemcpy(&ll_src, opts[i]->value, ETH_MAC_LEN);
      ll_src_found = true;
      break;
    }
  }

  // Handle the solicit request itself.
  kspin_lock(&nic->lock);
  for (int addr_idx = 0; addr_idx < NIC_MAX_ADDRS; ++addr_idx) {
    if (nic->addrs[addr_idx].a.addr.family == AF_INET6 &&
        (nic->addrs[addr_idx].state == NIC_ADDR_ENABLED ||
         nic->addrs[addr_idx].state == NIC_ADDR_TENTATIVE)) {
      if (kmemcmp(&nic->addrs[addr_idx].a.addr.a.ip6, &hdr->target,
                  sizeof(struct in6_addr)) == 0) {
        KLOG(DEBUG, "IPv6 NDP: found NIC %s with matching IP (%s)\n", nic->name,
             inet62str(&hdr->target, addrbuf));

        bool src_unspec = false;
        struct in6_addr reply_dst;
        if (in6_is_any(&ip_hdr->src_addr)) {
          KASSERT(0 == str2inet6("ff02::1", &reply_dst));
          src_unspec = true;
        } else {
          reply_dst = ip_hdr->src_addr;
        }

        // If the address is tentative, don't send a reply.
        if (nic->addrs[addr_idx].state == NIC_ADDR_TENTATIVE) {
          if (src_unspec) {
            ip6_nic_got_dup_solicit(nic, &nic->addrs[addr_idx]);
          }
          kspin_unlock(&nic->lock);
          return;
        }

        pbuf_t* pb = ndp_mkpkt(
            nic, false, &reply_dst, ICMPV6_NDP_NBR_ADVERT, &hdr->target,
            NDP_NBR_ADVERT_FLAG_SOLICITED | NDP_NBR_ADVERT_FLAG_OVERRIDE,
            ICMPV6_OPTION_TGT_LL_ADDR, nic->mac.addr);
        kspin_unlock(&nic->lock);
        if (!pb) {
          return;
        }

        // TODO(ipv6): handle non-blocking correctly (currently, if the neighbor
        // cache doesn't include the target's address, then this will send an
        // NDP solicit but not wait for the reply --- and the requester will
        // have to time out and try their solicit again).
        netaddr_t next_hop;
        next_hop.family = AF_INET6;
        next_hop.a.ip6 = ip_hdr->src_addr;
        if (!src_unspec && ll_src_found) {
          nbr_cache_insert(nic, next_hop, ll_src);
        }

        int result;
        if (src_unspec) {
          nic_mac_t eth_dst;
          ip6_multicast_mac(&reply_dst, eth_dst.addr);
          eth_add_hdr(pb, &eth_dst, &nic->mac, ET_IPV6);
          result = eth_send_raw(nic, pb);
        } else {
          result = eth_send(nic, next_hop, pb, ET_IPV6, false);
        }
        if (result) {
          KLOG(WARNING, "IPv6 NDP: unable to send reply to solicitation: %s\n",
               errorname(-result));
          pbuf_free(pb);
        }

        // Our job is done.
        return;
      }
    }
  }
  kspin_unlock(&nic->lock);
}

static bool handle_prefix(nic_t* nic, const ndp_option_prefix_t* prefix) {
  KASSERT_DBG(prefix->type == ICMPV6_OPTION_PREFIX);
  KASSERT_DBG(prefix->length == 4);
  char pretty[INET6_PRETTY_LEN], pretty2[INET6_PRETTY_LEN];
  if (!(prefix->flags & NDP_PREFIX_FLAG_ONLINK) ||
      !(prefix->flags & NDP_PREFIX_FLAG_AUTOCONF)) {
    KLOG(DEBUG, "ICMPv6: ignoring non-autoconf advertised router prefix %s/%d\n",
         inet62str(&prefix->prefix, pretty), prefix->prefix_len);
    return false;
  }
  if (prefix->prefix_len != 128 - nic->ipv6.iface_id_len) {
    KLOG(DEBUG,
         "ICMPv6: ignoring advertised router prefix %s/%d (incompatible prefix "
         "len)\n",
         inet62str(&prefix->prefix, pretty), prefix->prefix_len);
    return false;
  }

  // TODO(ipv6): handle valid and preferred times.

  // Create new address and attempt to configure it.
  network_t addr;
  addr.prefix_len = prefix->prefix_len;
  addr.addr.family = AF_INET6;
  // Must ignore all the bits after prefix_len; this accomplishes that by
  // requiring that the prefix len exactly matches the interface ID length, and
  // merging them.
  kmemcpy(&addr.addr.a.ip6, &prefix->prefix, sizeof(struct in6_addr));
  ip6_addr_merge(&addr.addr.a.ip6, &nic->ipv6.iface_id, nic->ipv6.iface_id_len);
  KLOG(INFO, "ipv6: found advertised prefix %s/%d; configuring address %s\n",
       inet62str(&prefix->prefix, pretty), prefix->prefix_len,
       inet62str(&addr.addr.a.ip6, pretty2));

  int result = ipv6_configure_addr(nic, &addr);
  if (result != 0) {
    KLOG(WARNING, "ipv6: unable to configure advertised prefix %s/%d: %s\n",
       inet62str(&prefix->prefix, pretty), prefix->prefix_len,
       errorname(-result));
  }
  return true;
}

static void handle_router_advert(nic_t* nic, const ip6_hdr_t* ip6_hdr,
                                 pbuf_t* pb) {
  const ndp_router_advert_t* hdr = (const ndp_router_advert_t*)pbuf_getc(pb);
  KASSERT(hdr->hdr.type == ICMPV6_NDP_ROUTER_ADVERT);
  if (hdr->hdr.code != 0) {
    KLOG(INFO, "ICMPv6 NDP: NDP packet with non-zero code, dropping\n");
    return;
  }
  if (pbuf_size(pb) < sizeof(ndp_router_advert_t)) {
    KLOG(INFO, "ICMPv6 NDP: NDP packet too short, dropping\n");
    return;
  }
  // TODO(ipv6): handle the current hop limit (and other fields).

  const int kMaxOpts = 10;
  const ndp_option_t* opts[kMaxOpts];
  size_t opts_offset = sizeof(ndp_router_advert_t);
  int num_opts = ndp_parse_opts(pbuf_get(pb) + opts_offset,
                                pbuf_size(pb) - opts_offset, opts, kMaxOpts);
  if (num_opts < 0) {
    KLOG(INFO, "ICMPv6: NDP bad options; dropping\n");
    return;
  }

  bool found_prefix = false;
  for (int i = 0; i < num_opts; ++i) {
    if (opts[i]->type == ICMPV6_OPTION_PREFIX) {
      if (opts[i]->len != 4) {
        KLOG(INFO, "ICMPv6 NDP: bad LL target option size\n");
        return;
      }

      const ndp_option_prefix_t* prefix = (ndp_option_prefix_t*)opts[i];
      found_prefix = handle_prefix(nic, prefix) || found_prefix;
    }
  }

  if (found_prefix) {
    kspin_lock(&nic->lock);
    nic->ipv6.gateway.valid = true;
    kmemcpy(&nic->ipv6.gateway.addr, &ip6_hdr->src_addr,
            sizeof(struct in6_addr));
    kspin_unlock(&nic->lock);
    // TODO(ipv6): set default route
  }
}

void ndp_rx(nic_t* nic, const ip6_hdr_t* ip_hdr, pbuf_t* pb) {
  const icmpv6_hdr_t* hdr = (const icmpv6_hdr_t*)pbuf_getc(pb);
  switch (hdr->type) {
    case ICMPV6_NDP_NBR_ADVERT:
      handle_advert(nic, ip_hdr, pb);
      pbuf_free(pb);
      return;

    case ICMPV6_NDP_NBR_SOLICIT:
      handle_solicit(nic, ip_hdr, pb);
      pbuf_free(pb);
      return;

    case ICMPV6_NDP_ROUTER_ADVERT:
      handle_router_advert(nic, ip_hdr, pb);
      pbuf_free(pb);
      return;
  }

  KLOG(DFATAL, "Unknown ICMPv6 NDP type %d\n", hdr->type);
  pbuf_free(pb);
}

// TODO(aoates): refactor the code so that this (and arp_send_request) can be
// called without the NIC lock held.
void ndp_send_request(nic_t* nic, const struct in6_addr* addr,
                      bool src_any_addr) {
  KASSERT_DBG(kspin_is_held(&nic->lock));
  // First calculate the IPv6 solicited-node multicast address.
  struct in6_addr dst_addr;
  ip6_solicited_node_addr(addr, &dst_addr);

  pbuf_t* pb = ndp_mkpkt(nic, src_any_addr, &dst_addr, ICMPV6_NDP_NBR_SOLICIT,
                         addr, 0, ICMPV6_OPTION_SRC_LL_ADDR, nic->mac.addr);
  if (!pb) {
    return;
  }

  nic_mac_t eth_dst;
  ip6_multicast_mac(&dst_addr, eth_dst.addr);
  eth_add_hdr(pb, &eth_dst, &nic->mac, ET_IPV6);
  int result = eth_send_raw(nic, pb);
  if (result) {
    KLOG(WARNING, "IPv6 NDP: unable to send NDP packet: %s\n",
         errorname(-result));
  }
}

void ndp_send_router_solicit(nic_t* nic) {
  KASSERT_DBG(kspin_is_held(&nic->lock));
  // Send to the all-routers multicast address.
  struct in6_addr dst_addr;
  KASSERT(0 == str2inet6("ff02::2", &dst_addr));

  pbuf_t* pb = ndp_mkpkt(nic, false, &dst_addr, ICMPV6_NDP_ROUTER_SOLICIT, NULL,
                         0, ICMPV6_OPTION_SRC_LL_ADDR, nic->mac.addr);
  if (!pb) {
    return;
  }

  nic_mac_t eth_dst;
  ip6_multicast_mac(&dst_addr, eth_dst.addr);
  eth_add_hdr(pb, &eth_dst, &nic->mac, ET_IPV6);
  int result = eth_send_raw(nic, pb);
  if (result) {
    KLOG(WARNING, "IPv6 NDP: unable to send NDP packet: %s\n",
         errorname(-result));
  }
}
