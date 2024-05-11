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

// Generic link-layer neighbor cache.  This handles ARP for IPv4 and NDP for
// IPv6, and manages a common neighbor cache for each NIC that covers both
// protocols.
#ifndef APOO_NET_NEIGHBOR_CACHE_OPS_H
#define APOO_NET_NEIGHBOR_CACHE_OPS_H

#include "dev/net/nic.h"
#include "net/addr.h"
#include "net/neighbor_cache.h"

// Do a cache lookup.  Returns 0 on success, or -error.  If the timeout is 0,
// returns without blocking.
int nbr_cache_lookup(nic_t* nic, netaddr_t addr, nbr_cache_entry_t* result,
                     int timeout_ms);

// Add an entry to the given neighbor cache.
// Interrupt-safe.
void nbr_cache_insert(nic_t* nic, netaddr_t addr, const uint8_t* mac);

#endif
