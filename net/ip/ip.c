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

#include "net/ip/ip.h"

#include "arch/common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "net/ip/checksum.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/route.h"
#include "net/link_layer.h"
#include "net/socket/raw.h"
#include "net/util.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

static bool validate_hdr_v4(const pbuf_t* pb) {
  if (pbuf_size(pb) < sizeof(ip4_hdr_t)) {
    KLOG(DEBUG, "net: truncated IP packet\n");
    return false;
  }
  const ip4_hdr_t* hdr = (const ip4_hdr_t*)pbuf_getc(pb);
  if (ip4_version(*hdr) != 4) {
    KLOG(DEBUG, "net: IP packet with bad version %d\n", ip4_version(*hdr));
    return false;
  }
  if (ip4_ihl(*hdr) < 5) {
    KLOG(DEBUG, "net: IP packet with bad IHL %d\n", ip4_ihl(*hdr));
    return false;
  }
  const size_t hdr_len = ip4_ihl(*hdr) * sizeof(uint32_t);
  const size_t total_len = btoh16(hdr->total_len);
  if (total_len < hdr_len || total_len > pbuf_size(pb)) {
    KLOG(DEBUG, "net: IP packet with bad length %d\n", hdr->total_len);
    return false;
  }
  if ((ip4_flags(*hdr) & IPV4_FLAG_MF) || ip4_fragoff(*hdr) > 0) {
    KLOG(DEBUG, "net: fragmented IP packet\n");
    return false;
  }
  if (ip_checksum(hdr, hdr_len) != 0) {
    KLOG(DEBUG, "net: IP packet with bad checksum\n");
    return false;
  }
  return true;
}

int ip_send(pbuf_t* pb) {
  if (pbuf_size(pb) < sizeof(ip4_hdr_t)) {
    KLOG(INFO, "net: rejecting too-short IP packet\n");
    return -EINVAL;
  }

  ip4_hdr_t* hdr = (ip4_hdr_t*)pbuf_get(pb);
  if (hdr->version_ihl >> 4 != 4) {
    KLOG(INFO, "net: rejecting IP packet with bad version %d\n",
         hdr->version_ihl >> 4);
    return -EINVAL;
  }

  netaddr_t dst;
  dst.family = AF_INET;
  dst.a.ip4.s_addr = hdr->dst_addr;
  ip_routed_t route;
  if (ip_route(dst, &route) == false) {
    char addrbuf[INET_PRETTY_LEN];
    KLOG(INFO, "net: unable to route packet to %s\n",
         inet2str(hdr->dst_addr, addrbuf));
    return -EINVAL;  // TODO
  }

  return net_link_send(route.nic, route.nexthop, pb, ET_IPV4);
}

void ip_recv(nic_t* nic, pbuf_t* pb) {
  // Verify the packet.
  if (!validate_hdr_v4(pb)) {
    KLOG(INFO, "net: dropping invalid IP packet\n");
    // TODO(aoates): increment stats.
    pbuf_free(pb);
    return;
  }

  const ip4_hdr_t* hdr = (const ip4_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(ip4_version(*hdr) == 4);
  char buf1[INET_PRETTY_LEN], buf2[INET_PRETTY_LEN];
  KLOG(DEBUG2, "ip rx(%s): %s -> %s, protocol=%d\n", nic->name,
       inet2str(hdr->src_addr, buf1), inet2str(hdr->dst_addr, buf2),
       hdr->protocol);

  struct sockaddr_in src_addr;
  src_addr.sin_family = AF_INET;
  src_addr.sin_addr.s_addr = hdr->src_addr;
  src_addr.sin_port = 0;
  sock_raw_dispatch(pb, ET_IPV4, hdr->protocol, (struct sockaddr*)&src_addr,
                    sizeof(src_addr));
  pbuf_free(pb);
}
