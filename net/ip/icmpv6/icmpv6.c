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
#include "net/ip/icmpv6/icmpv6.h"

#include "common/kassert.h"
#include "common/kstring.h"
#include "net/eth/mac.h"
#include "net/ip/checksum.h"
#include "net/ip/icmpv6/ndp.h"
#include "net/ip/icmpv6/protocol.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/ip6_multicast.h"
#include "net/pbuf.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

bool icmpv6_recv(nic_t* nic, const ip6_hdr_t* ip_hdr, size_t offset,
                 pbuf_t* pb) {
  KASSERT_DBG(pbuf_size(pb) >= offset);
  if (pbuf_size(pb) - offset < sizeof(icmpv6_hdr_t)) {
    KLOG(INFO, "ICMPv6: dropping too-short packet\n");
    return false;
  }


  // Verify the checksum first.
  ip6_pseudo_hdr_t phdr;
  kmemcpy(&phdr.src_addr, &ip_hdr->src_addr, sizeof(struct in6_addr));
  kmemcpy(&phdr.dst_addr, &ip_hdr->dst_addr, sizeof(struct in6_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = ip_hdr->payload_len;
  phdr.next_hdr = ip_hdr->next_hdr;
  if (ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb) + offset,
                   pbuf_size(pb) - offset) != 0) {
    KLOG(INFO, "ICMPv6: dropping packet with invalid checksum\n");
    return false;
  }

  pbuf_pop_header(pb, offset);
  const icmpv6_hdr_t* hdr = (const icmpv6_hdr_t*)pbuf_getc(pb);
  switch (hdr->type) {
    case ICMPV6_NDP_NBR_SOLICIT:
    case ICMPV6_NDP_NBR_ADVERT:
    case ICMPV6_NDP_ROUTER_ADVERT:
      ndp_rx(nic, ip_hdr, pb);
      return true;

    case ICMPV6_MLD_QUERY:
      ip6_multicast_handle_query(nic, ip_hdr, pb);
      return true;
  }

  KLOG(INFO, "ICMPv6: unknown ICMPv6 type %d\n", hdr->type);
  return false;
}
