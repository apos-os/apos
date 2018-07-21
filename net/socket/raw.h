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

// Raw sockets.
#ifndef APOO_NET_SOCKET_RAW_H
#define APOO_NET_SOCKET_RAW_H

#include "common/list.h"
#include "net/addr.h"
#include "net/socket/socket.h"
#include "net/eth/ethertype.h"
#include "net/pbuf.h"
#include "proc/kthread.h"

typedef struct socket_raw {
  socket_t base;

  // The local bound address.  If unbound, family will be AF_UNSPEC.
  netaddr_t bind_addr;

  // The connected address.  If unconnected, family will be AF_UNSPEC.
  netaddr_t connected_addr;

  // List of queued packets.
  // TODO(aoates): cap amount of buffered data.
  list_t rx_queue;

  // Wait queue for packets to be received.
  kthread_queue_t wait_queue;

  // Link on raw socket linked list.
  list_t* sock_list;
  list_link_t link;
} socket_raw_t;

// Create a raw socket.
int sock_raw_create(int domain, int protocol, socket_t** out);

// Handle a IP-layer (or equivalent) packet.  If necessary, it will be
// dispatched to any active raw sockets for the given protocol.  Ownership is
// _not_ taken.
//
// Interrupt safe.
// TODO(aoates): switch this to use deferred interrupts when they exist.
void sock_raw_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol,
                       const struct sockaddr* src_addr, socklen_t addrlen);

#endif
