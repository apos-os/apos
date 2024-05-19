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

// Implementation of the ICMPv6 Neighbor Discovery Protocol components.
#ifndef APOO_NET_IP_ICMPV6_NDP_H
#define APOO_NET_IP_ICMPV6_NDP_H

#include "dev/net/nic.h"
#include "net/ip/ip6_hdr.h"
#include "net/pbuf.h"

// Handle an inbound NDP packet.
void ndp_rx(nic_t* nic, const ip6_hdr_t* ip_hdr, pbuf_t* pb);

// Send a request for the given address on the nic.  Requires the nic be locked.
void ndp_send_request(nic_t* nic, const struct in6_addr* addr);

#endif
