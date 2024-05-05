// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_ETH_ETH_H
#define APOO_NET_ETH_ETH_H

#include <stdint.h>

#include "dev/net/nic.h"
#include "net/eth/ethertype.h"
#include "net/eth/mac.h"
#include "net/pbuf.h"

// An ethernet frame header.  Everything assumed to be in network byte order.
typedef struct __attribute__((packed)) {
  uint8_t mac_dst[ETH_MAC_LEN];
  uint8_t mac_src[ETH_MAC_LEN];
  uint16_t ethertype;
} eth_hdr_t;

_Static_assert(sizeof(eth_hdr_t) == 14, "wrong eth_hdr_t size");

// Handle and dispatch an outbound packet for the given NIC.  Does an ARP (or
// equivalent) lookup to find the link-layer address.  May block.
//
// The packet should NOT have an ethernet frame header on it already.
//
// If allow_blocking is false, then the request may fail with EWOULDBLOCK if the
// ARP cache doesn't have an appropriate entry.
int eth_send(nic_t* nic, netaddr_t next_hop, pbuf_t* pb, ethertype_t protocol,
             bool allow_blocking);

// Handle and dispatch an inbound packet.  Takes ownership of the buffer.
void eth_recv(nic_t* nic, pbuf_t* pb);

// Adds (prepends) an ethernet header to the given packet.
void eth_add_hdr(pbuf_t* pb, const nic_mac_t* mac_dst, const nic_mac_t* mac_src,
                 ethertype_t ethertype);

#endif
