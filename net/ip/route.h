// Copyright 2018 Andrew Oates.  All Rights Reserved.
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

// Routing logic.  Given an IP packet, decides where it should go.
#ifndef APOO_NET_IP_ROUTE_H
#define APOO_NET_IP_ROUTE_H

#include "dev/net/nic.h"
#include "net/addr.h"

// A routing decision.
typedef struct {
  nic_t* nic;  // The NIC to send the packet on, or NULL if we can't route.
  netaddr_t nexthop;  // The next hop to go through.  May be the destination
                      // itself, or a gateway address.
  netaddr_t src;      // The source address to use, if necessary.
} ip_routed_t;

// Find a route for the given destination address.
bool ip_route(netaddr_t dst, ip_routed_t* result);

// Set the default route for the address's address family.  Pass an AF_UNSPEC
// address to disable the default route for the given address family.
// TODO(aoates): support arbitrary routing rules.
void ip_set_default_route(addrfam_t family, netaddr_t nexthop,
                          const char* nic_name);
void ip_get_default_route(addrfam_t family, netaddr_t* nexthop, char* nic_name);

#endif
