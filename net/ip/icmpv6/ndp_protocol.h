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

#endif
