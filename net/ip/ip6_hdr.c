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
#include "net/ip/ip6_hdr.h"

#include "common/endian.h"
#include "common/kassert.h"
#include "common/kstring.h"

#define IP_DEFAULT_TTL 64

void ip6_add_hdr(pbuf_t* pb, const struct in6_addr* src,
                 const struct in6_addr* dst, uint8_t protocol,
                 uint32_t flow_label) {
  pbuf_push_header(pb, sizeof(ip6_hdr_t));
  ip6_hdr_t* hdr = (ip6_hdr_t*)pbuf_get(pb);
  hdr->version_tc_flow = htob32(6 << 28);  // Version 0, TC/flow = 0.
  hdr->version_tc_flow |= htob32(flow_label & 0xfffff);
  hdr->payload_len = htob16(pbuf_size(pb) - sizeof(ip6_hdr_t));
  hdr->next_hdr = protocol;
  hdr->hop_limit = IP_DEFAULT_TTL;
  kmemcpy(&hdr->src_addr, src, sizeof(struct in6_addr));
  kmemcpy(&hdr->dst_addr, dst, sizeof(struct in6_addr));
}

void ip6_multicast_mac(const struct in6_addr* addr, uint8_t* mac) {
  KASSERT_DBG(addr->s6_addr[0] == 0xff);
  KASSERT_DBG(addr->s6_addr[1] == 0x02);
  mac[0] = 0x33;
  mac[1] = 0x33;
  kmemcpy(&mac[2], &addr->s6_addr[12], 4);
}
