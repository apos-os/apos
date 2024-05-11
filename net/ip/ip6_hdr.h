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

#ifndef APOO_NET_IP_IP6_HDR_H
#define APOO_NET_IP_IP6_HDR_H

#include <stdint.h>

#include "net/pbuf.h"
#include "user/include/apos/net/socket/inet.h"

// An IPv6 packet header.  Everything in network byte order unless otherwise
// specified at usage site.
typedef struct __attribute__((packed)) {
  uint32_t version_tc_flow;
  uint16_t payload_len;
  uint8_t next_hdr;
  uint8_t hop_limit;
  struct in6_addr src_addr;
  struct in6_addr dst_addr;
} ip6_hdr_t;

_Static_assert(sizeof(ip6_hdr_t) == 40, "ip6_hdr_t wrong size");

#define ip6_version(h) (btoh32((h).version_tc_flow) >> 28)
#define ip6_traffic_class(h) ((btoh32((h).version_tc_flow) >> 20) & 0xff)
#define ip6_flow(h) (btoh32((h).version_tc_flow) & 0x0fffff)

// Adds (prepends) an IPv6 header to the given packet.
void ip6_add_hdr(pbuf_t* pb, const struct in6_addr* src,
                 const struct in6_addr* dst, uint8_t protocol,
                 uint32_t flow_label);

// IPv6 pseudo-header for upper layer checksum calculations.
typedef struct __attribute__((packed)) {
  struct in6_addr src_addr;
  struct in6_addr dst_addr;
  uint32_t payload_len;
  uint8_t _zeroes[3];
  uint8_t next_hdr;
} ip6_pseudo_hdr_t;

_Static_assert(sizeof(ip6_pseudo_hdr_t) == 40, "ip6_pseudo_hdr_t wrong size");

// Calculate the multicast Ethernet MAC address for the given IPv6 multicast
// address.
void ip6_multicast_mac(const struct in6_addr* addr, uint8_t* mac);

#endif
