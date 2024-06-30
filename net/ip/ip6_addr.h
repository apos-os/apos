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

#ifndef APOO_NET_IP_IP6_ADDR_H
#define APOO_NET_IP_IP6_ADDR_H

#include "dev/net/nic.h"
#include "net/addr.h"
#include "user/include/apos/net/socket/inet.h"

// Returns the number of bits shared between the two addresses.
int ip6_common_prefix(const struct in6_addr* A, const struct in6_addr* B);

// Compare two IPv6 source addresses per RFC 6724.  Returns a negative number if
// if the first address is lower in preference than the second.
//
// Does not implement the full sorting criteria --- in particular, assumes that
// all addresses are on the outgoing interface, among other constraints.
int ip6_src_addr_cmp(const nic_addr_t* A, const nic_addr_t* B,
                     const netaddr_t* dst, const nic_t* out_nic);

// Returns true if the given address is a link-local address.
bool ip6_is_link_local(const struct in6_addr* addr);

// Create the solicited-node multicast address for the given address.
void ip6_solicited_node_addr(const struct in6_addr* addr_in,
                             struct in6_addr* mc_addr_out);

#endif
