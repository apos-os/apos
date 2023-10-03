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

// Common definitions for all internet protocol code.
#ifndef APOO_NET_IP_IP_H
#define APOO_NET_IP_IP_H

#include "dev/net/nic.h"
#include "net/pbuf.h"

// Send an IP packet out onto the network.  May block.  The packet must already
// have an IP header.
int ip_send(pbuf_t* pb, bool allow_block);

// Handle and dispatch an inbound packet.  Takes ownership of the buffer.
void ip_recv(nic_t* nic, pbuf_t* pb);

#endif
