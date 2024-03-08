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

#ifndef APOO_NET_ETH_ARP_ARP_H
#define APOO_NET_ETH_ARP_ARP_H

#include "dev/net/nic.h"
#include "net/pbuf.h"
#include "user/include/apos/net/socket/inet.h"

// Handle an inbound ARP packet.
void arp_rx(nic_t* nic, pbuf_t* pb);

// Send a request for the given address on the nic.  Requires the nic be locked.
void arp_send_request(nic_t* nic, in_addr_t addr);

#endif
