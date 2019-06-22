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

#ifndef APOO_NET_SOCKET_UDP_H
#define APOO_NET_SOCKET_UDP_H

#include "net/eth/ethertype.h"
#include "net/pbuf.h"
#include "net/socket/socket.h"
#include "proc/kthread.h"
#include "user/include/apos/net/socket/inet.h"

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t checksum;
} __attribute__((packed)) udp_hdr_t;

typedef struct socket_udp {
  socket_t base;

  // The local bound address.  If unbound, family will be AF_UNSPEC.
  struct sockaddr_storage bind_addr;

  // The connected peer address.  If unconnected, family will be AF_UNSPEC.
  struct sockaddr_storage connected_addr;

  // List of queued packets.
  // TODO(aoates): cap amount of buffered data.
  list_t rx_queue;

  // Wait queue for packets to be received.
  kthread_queue_t wait_queue;
  poll_event_t poll_event;
} socket_udp_t;

int sock_udp_create(socket_t** out);

// Handles an IP packet.  The packet is dispatched to a matching socket (if one
// exists).  Returns true if the packet was dispatched, false if not.  If false
// is returned, the caller retains ownership of the packet.
//
// Deferred-interrupt safe.
bool sock_udp_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol);

#endif
