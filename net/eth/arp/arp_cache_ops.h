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

#ifndef APOO_NET_ETH_ARP_ARP_CACHE_OPS_H
#define APOO_NET_ETH_ARP_ARP_CACHE_OPS_H

#include "dev/net/nic.h"
#include "net/eth/arp/arp_cache.h"
#include "user/include/apos/net/socket/inet.h"

// Do an ARP lookup.  Returns 0 on success, or -error.  If the timeout is 0,
// returns without blocking.
int arp_cache_lookup(nic_t* nic, in_addr_t addr, arp_cache_entry_t* result,
                     int timeout_ms);

// Add an entry to the given ARP cache.
// Interrupt-safe.
// TODO(aoates): make this deferred-interrupt-safe when that's a thing.
void arp_cache_insert(nic_t* nic, in_addr_t addr, const uint8_t* mac);

#endif
