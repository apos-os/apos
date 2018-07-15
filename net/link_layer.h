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

// Thin layer to handle link-layer packet rx and tx.  On the RX side, receives
// packets from the link-level-specific layer and dispatches based on the
// protocol.  On the TX side, receives packets bound for a particular NIC and
// forwards to the appropriate protocol stack.
#ifndef APOO_NET_LINK_LAYER_H
#define APOO_NET_LINK_LAYER_H

#include "dev/net/nic.h"
#include "net/addr.h"
#include "net/eth/ethertype.h"
#include "net/pbuf.h"

// Transmits the packet on the NIC, dispatching to the appropriate L2 stack.
// Returns 0 on success, or -error.
int net_link_send(nic_t* nic, netaddr_t next_hop, pbuf_t* pb,
                  ethertype_t protocol);

// Handles a packet recieved by a particular link layer stack.
void net_link_recv(nic_t* nic, pbuf_t* pb, ethertype_t protocol);

#endif
