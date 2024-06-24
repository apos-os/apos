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

#ifndef APOO_NET_IP_IP6_MULTICAST_H
#define APOO_NET_IP_IP6_MULTICAST_H

#include "dev/net/nic.h"
#include "net/ip/ip6_hdr.h"
#include "user/include/apos/net/socket/inet.h"

// Join the IPv6 multicast address on the given NIC.
int ip6_multicast_join(nic_t* nic, const struct in6_addr* addr);

// Leave the IPv6 multicast address.  Leaves should be paired 1:1 with joins.
int ip6_multicast_leave(nic_t* nic, const struct in6_addr* addr);

// Handle an incoming ICMPv6 MLD query.
void ip6_multicast_handle_query(nic_t* nic, const ip6_hdr_t* ip_hdr,
                                pbuf_t* pb);

#endif
