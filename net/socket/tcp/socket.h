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

  // Current error on the socket, or zero.
  int error;

  // Refcount (for internal TCP usage --- all external references are via a file
  // descriptor, which consumes one ref here).
  refcount_t ref;

  // The local bound address.  If unbound, family will be AF_UNSPEC.
  struct sockaddr_storage bind_addr;

  // The connected peer address.  If unconnected, family will be AF_UNSPEC.
  struct sockaddr_storage connected_addr;

  // Send/receive buffers.
  circbuf_t send_buf;
  circbuf_t recv_buf;

  long connect_timeout_ms;
  long recv_timeout_ms;
  long send_timeout_ms;

  // TCP state variables.
  uint32_t send_unack;    // My first unacknowledged sequence number.
  uint32_t send_next;     // My next sequence number to send.
  uint32_t send_wndsize;  // The send window size (from their side).
  uint32_t recv_next;     // Their next sequence number expected.
  uint32_t recv_wndsize;  // Receive window size (my window)
  uint32_t cwnd;          // Congestion window size.
  uint32_t mss;           // Maximum segment size.

  poll_event_t poll_event;

  kthread_queue_t q;

  // Guards complex compound user-driven socket operations.
  kmutex_t mu;

  // Protects data structures touched by defints and protocol-driven state
  // transitions.
  kspinlock_t spin_mu;
} socket_tcp_t;

// Categories of socket states (for internal use).
typedef enum {
  // A connection has not yet been established, or is being established; data
  // cannot flow yet.
  TCPSTATE_PRE_ESTABLISHED,

  // Connection is established or may be in the process of closing; data may
  // still be able to flow in one or both directions.
  TCPSTATE_ESTABLISHED,

  // Connection is in the process of closing or is closed; no new data may flow
  // in either direction anymore (ACKs and retransmits may still).
  TCPSTATE_POST_ESTABLISHED,
} socktcp_state_type_t;

socktcp_state_type_t get_state_type(socktcp_state_t s);

#endif
