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

#ifndef APOO_NET_ETH_ARP_ARP_PACKET_H
#define APOO_NET_ETH_ARP_ARP_PACKET_H

#include <stdint.h>

#include "net/pbuf.h"

// ARP packet format (assuming ethernet and ipv4).  Everything in
// network-byte-order.
typedef struct __attribute__((packed)) {
  uint16_t htype;  // Hardware type
  uint16_t ptype;  // Protocol type
  uint8_t hlen;    // Hardware address length
  uint8_t plen;    // Protocol address length
  uint16_t oper;   // Operation
  uint8_t sha[6];  // Sender hardware address
  uint8_t spa[4];  // Sender protocol address
  uint8_t tha[6];  // Target hardware address
  uint8_t tpa[4];  // Target protocol address
} arp_packet_t;

typedef enum {
  ARP_HTYPE_ETH = 1,
} arp_htype_t;

typedef enum {
  ARP_OPER_REQUEST = 1,
  ARP_OPER_REPLY = 2,
} arp_oper_t;

_Static_assert(sizeof(arp_packet_t) == 28, "bad arp_packet_t size");

pbuf_t* arp_mkpacket(arp_oper_t oper);

#endif
