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

#ifndef APOO_NET_IP_ICMPV6_NDP_PROTOCOL_H
#define APOO_NET_IP_ICMPV6_NDP_PROTOCOL_H

#include "net/ip/icmpv6/protocol.h"
#include "user/include/apos/net/socket/inet.h"

typedef struct __attribute__((packed)) {
  icmpv6_hdr_t hdr;
  uint32_t reserved;
  struct in6_addr target;
} ndp_nbr_solict_t;

typedef struct __attribute__((packed)) {
  icmpv6_hdr_t hdr;
  uint32_t flags;
  struct in6_addr target;
} ndp_nbr_advert_t;

typedef struct __attribute__((packed)) {
  icmpv6_hdr_t hdr;
  uint32_t reserved;
} ndp_router_solict_t;

typedef struct __attribute__((packed)) {
  icmpv6_hdr_t hdr;
  uint8_t cur_hop_limit;
  uint8_t router_flags;
  uint16_t lifetime;
  uint32_t reachable_time;
  uint32_t retrans_timer;
} ndp_router_advert_t;

typedef struct __attribute__((packed)) {
  uint8_t type;
  uint8_t length;
  uint8_t prefix_len;
  uint8_t flags;
  uint32_t valid_lifetime;
  uint32_t pref_lifetime;
  uint32_t reserved;
  struct in6_addr prefix;
} ndp_option_prefix_t;

#define NDP_PREFIX_FLAG_ONLINK 0x80
#define NDP_PREFIX_FLAG_AUTOCONF 0x40

#define NDP_NBR_ADVERT_FLAG_ROUTER (1 << 31)
#define NDP_NBR_ADVERT_FLAG_SOLICITED (1 << 30)
#define NDP_NBR_ADVERT_FLAG_OVERRIDE (1 << 29)

#endif
