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

#ifndef APOO_NET_SOCKET_TCP_SOCKET_H
#define APOO_NET_SOCKET_TCP_SOCKET_H

#include "common/circbuf.h"
#include "common/list.h"
#include "common/refcount.h"
#include "net/socket/socket.h"
#include "proc/kthread.h"
#include "vfs/vnode.h"

typedef enum {
  TCP_CLOSED,
  TCP_CLOSED_DONE,  // The connection is finished and the socket can't be reused
  TCP_SYN_SENT,
  TCP_ESTABLISHED,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
} socktcp_state_t;

typedef struct socket_tcp {
  socket_t base;

  // Current state of the socket.
  socktcp_state_t state;

  // Refcount (for internal TCP usage --- all external references are via a file
  // descriptor, which consumes one ref here).
  refcount_t ref;

  // The local bound address.  If unbound, family will be AF_UNSPEC.
  struct sockaddr_storage bind_addr;

  // The connected peer address.  If unconnected, family will be AF_UNSPEC.
  struct sockaddr_storage connected_addr;

  // Read buffer.
  circbuf_t rx_buf;

  uint32_t seq;
  int wndsize;

  // The last sequence number and ack seen from the other side.
  uint32_t remote_seq;  // The next sequence number expected.
  uint32_t remote_ack;
  int remote_wndsize;

  poll_event_t poll_event;

  kthread_queue_t q;

  // Guards complex compound user-driven socket operations.
  kmutex_t mu;

  // Protects data structures touched by defints and protocol-driven state
  // transitions.
  kspinlock_t spin_mu;
} socket_tcp_t;

#endif
