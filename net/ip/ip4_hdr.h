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

#ifndef APOO_NET_IP_IP4_HDR_H
#define APOO_NET_IP_IP4_HDR_H

#include <stdint.h>

#include "net/pbuf.h"
#include "user/include/apos/net/socket/inet.h"

// An IPv4 packet header.  Everything in network byte order unless otherwise
// specified at usage site.
typedef struct __attribute__((packed)) {
  uint8_t version_ihl;
  uint8_t dscp_ecn;
  uint16_t total_len;
  uint16_t id;
  uint16_t flags_fragoff;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t hdr_checksum;
  in_addr_t src_addr;
  in_addr_t dst_addr;
} ip4_hdr_t;

_Static_assert(sizeof(ip4_hdr_t) == 20, "ip4_hdr_t wrong size");

#define ip4_version(h) ((h).version_ihl >> 4)
#define ip4_ihl(h) ((h).version_ihl & 0x0f)
#define ip4_dscp(h) ((h).dscp_ecn >> 2)
#define ip4_ecn(h) ((h).dscp_ecn & 0x03)
#define ip4_flags(h) (btoh16((h).flags_fragoff) >> 13)
#define ip4_fragoff(h) (btoh16((h).flags_fragoff) & 0x1fff)

#define IPV4_FLAG_MF 0x1
#define IPV4_FLAG_DF 0x2

// Adds (prepends) an IP header to the given packet.  Calculates the checksum.
void ip4_add_hdr(pbuf_t* pb, in_addr_t src, in_addr_t dst, uint8_t protocol);

// Pseudo-header for calculating UDP and TCP checksums.
typedef struct {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t zeroes;
  uint8_t protocol;
  uint16_t length;
} __attribute__((packed)) ip4_pseudo_hdr_t;

#endif
