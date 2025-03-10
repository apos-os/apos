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

#ifndef APOO_NET_IP_IP6_H
#define APOO_NET_IP_IP6_H

#include "dev/net/nic.h"

// Initialize and clean up IPv6 state on the given NIC.
void ipv6_init(nic_t* nic);
void ipv6_cleanup(nic_t* nic);

// Returns default options (can be passed directly to ipv6_enable()).
const nic_ipv6_options_t* ipv6_default_nic_opts(void);

// Configures the given IP address on the NIC.  Adds it to the NIC, sets the
// state to TENTATIVE, and begins duplicate detection.  This operation may fail
// synchronously (e.g. if there are no more address slots), or asynchronously
// (e.g. if duplicate detection finds a conflict).
int ipv6_configure_addr(nic_t* nic, const network_t* addr);

// Enable IPv6 on the given NIC.  Copies the passed options.  If autoconfigure
// is set, configures a link-local address and kicks off the configuration
// process.  No-op if the NIC already has an IPv6 address.
void ipv6_enable(nic_t* nic, const nic_ipv6_options_t* opts);

// Send an IPv6 packet out onto the network.  May block.  The packet must
// already have an IPv6 header.  Unconditionally takes ownership of the packet
// (on success as well as failure).
int ip6_send(pbuf_t* pb, bool allow_block);

void ip6_recv(nic_t* nic, pbuf_t* pb);

#endif
