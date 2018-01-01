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

#include "net/ip/ip4_hdr.h"

#include "arch/common/endian.h"
#include "common/kassert.h"

#define IP_DEFAULT_TTL 64

void ip4_add_hdr(pbuf_t* pb, in_addr_t src, in_addr_t dst, uint8_t protocol) {
  pbuf_push_header(pb, sizeof(ip4_hdr_t));
  ip4_hdr_t* hdr = (ip4_hdr_t*)pbuf_get(pb);
  hdr->version_ihl = 0x45;  // IPv4, header 5 words long.
  hdr->dscp_ecn = 0;
  hdr->total_len = htob16(pbuf_size(pb));
  hdr->id = htob16(0);
  hdr->flags_fragoff = 0;
  hdr->ttl = IP_DEFAULT_TTL;
  hdr->protocol = protocol;
  hdr->hdr_checksum = 0;
  hdr->src_addr = src;
  hdr->dst_addr = dst;

  // Calculate the checksum.
  // TODO(aoates): only do this if needed (i.e. because we can't offload it to
  // the NIC, or ignore it on the loopback device, etc).
  uint32_t checksum = 0;
  const uint8_t* hdr_data = pbuf_get(pb);
  const size_t hdr_len = sizeof(ip4_hdr_t);
  KASSERT_DBG(hdr_len % 2 == 0);
  for (size_t i = 0; i < sizeof(ip4_hdr_t) / 2; ++i) {
    checksum += (hdr_data[2 * i] << 8) | hdr_data[2 * i + 1];
    checksum = (checksum >> 16) + (checksum & 0xFFFF);  // End-around carry.
  }
  KASSERT_DBG((checksum & 0xFFFF0000) == 0);
  checksum = ~checksum;
  hdr->hdr_checksum = htob16(checksum);
}
