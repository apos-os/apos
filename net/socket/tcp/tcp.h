// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_SOCKET_TCP_TCP_H
#define APOO_NET_SOCKET_TCP_TCP_H

#include "net/eth/ethertype.h"
#include "net/pbuf.h"
#include "net/socket/socket.h"

int sock_tcp_create(int domain, int type, int protocol, socket_t** out);

void tcp_init(void);

// Handles an IP packet.  The packet is dispatched to a matching socket (if one
// exists).  Returns true if the packet was dispatched, false if not.  If false
// is returned, the caller retains ownership of the packet.
//
// Deferred-interrupt safe.
bool sock_tcp_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol,
                       ssize_t header_len);

// Returns the number of connected TCP sockets.
int tcp_num_connected_sockets(void);

#endif
