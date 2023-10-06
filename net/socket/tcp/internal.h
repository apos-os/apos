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

#ifndef APOO_NET_SOCKET_TCP_INTERNAL_H
#define APOO_NET_SOCKET_TCP_INTERNAL_H

#include "common/attributes.h"
#include "common/hashtable.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/socket.h"

typedef struct {
  // Map from 5-tuple hash to socket_tcp_t* of all sockets that are connected or
  // connecting (i.e. that are expected to match a specific 5-tuple of incoming
  // packets).  Sockets are here if they have a full 5-tuple, and in the TCP
  // sockmap if they have only a bound address.  By construction, no more than
  // one socket can be in the sockmap bound to a particular address (including
  // the any-addr as a wildcard).  On the other hand, whether a new socket can
  // be bound to an address while others are in `connected_sockets` is policy.
  //
  // For orphaned sockets (ones with no associated file descriptor but are
  // still protocol-active, e.g. in TIME_WAIT), the only reference to them will
  // be either connected_sockets or the bound sockmap.
  htbl_t connected_sockets;  // GUARDED_BY(mu)

  kspinlock_t lock;
} tcp_state_t;

extern tcp_state_t g_tcp;

typedef uint32_t tcp_key_t;
tcp_key_t tcp_key(const struct sockaddr* local, const struct sockaddr* remote);

// Helpers for comparing sequence numbers.  We assume (arbitrarily) that
// the sequence number space is split in half (modulo 2^32).
static inline ALWAYS_INLINE bool seq_gt(uint32_t a, uint32_t b) {
  // TODO(aoates): there must be a more elegant way of doing this.
  return ((a > b) && (a - b <= UINT32_MAX / 2)) ||
         ((b > a) && (b - a > UINT32_MAX / 2));
}

static inline ALWAYS_INLINE bool seq_ge(uint32_t a, uint32_t b) {
  return (a == b) || seq_gt(a, b);
}

static inline ALWAYS_INLINE bool seq_lt(uint32_t a, uint32_t b) {
  return seq_gt(b, a);
}

static inline ALWAYS_INLINE bool seq_le(uint32_t a, uint32_t b) {
  return seq_ge(b, a);
}

#endif
