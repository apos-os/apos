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

#ifndef APOO_NET_IP_ICMPV6_PROTOCOL_H
#define APOO_NET_IP_ICMPV6_PROTOCOL_H

#include <stdint.h>

// Common header for all ICMPv6 packets.  All packets have at least one data
// word (4 bytes) after this header.
typedef struct __attribute__((packed)) {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
} icmpv6_hdr_t;

_Static_assert(sizeof(icmpv6_hdr_t) == 4, "icmpv6_hdr_t wrong size");

// ICMPv6 message types.
#define ICMPV6_NDP_ROUTER_SOLICIT 133
#define ICMPV6_NDP_ROUTER_ADVERT 134
#define ICMPV6_NDP_NBR_SOLICIT 135
#define ICMPV6_NDP_NBR_ADVERT 136
#define ICMPV6_MLD_QUERY 130
#define ICMPV6_MLD_LISTENER_REPORT 143

// ICMPv6 option types.
#define ICMPV6_OPTION_SRC_LL_ADDR 1
#define ICMPV6_OPTION_TGT_LL_ADDR 2
#define ICMPV6_OPTION_PREFIX 3

#endif
