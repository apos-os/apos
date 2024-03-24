// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

// A TCP-specific socket map.
#ifndef APOO_NET_SOCKET_TCP_SOCKMAP_H
#define APOO_NET_SOCKET_TCP_SOCKMAP_H

#include "common/hashtable.h"
#include "net/socket/tcp/socket.h"
#include "user/include/apos/net/socket/socket.h"

// TCP socket map data structure.  Tracks both bound and connected sockets.  It
// does not do any internal synchronization or refcounting of the sockets; the
// sockets are treated as opaque pointers that are cast to/from type
// socket_tcp_t* for convenience.
//
// Thread-compatible.
typedef struct {
  sa_family_t family;
  int eph_port_min;
  int eph_port_max;

  // Map (tcp_key_t -> sm_list_t) for each local address:port pair.  Each
  // contains a list of sockets bound to that local address, which may be
  // half-bound or fully connected.
  htbl_t bound_sockets;

  // Map (tcp_key_t -> sm_entry_t) from 5-tuple hash to socket_tcp_t* of all
  // sockets that are connected or connecting (i.e. that are expected to match a
  // specific 5-tuple of incoming packets).  Sockets are here if they have a
  // full 5-tuple.
  htbl_t connected_sockets;

  // Map (port -> sm_list_t) from port to entry list.
  htbl_t port_table;
} tcp_sockmap_t;

// Initialize the sockmap.
void tcpsm_init(tcp_sockmap_t* sm, sa_family_t family, int eph_port_min,
                int eph_port_max);

void tcpsm_cleanup(tcp_sockmap_t* sm);

// Looks up a socket associated with the given local and remote address pair.
// Returns it with a reference.  Multiple sockets may match the 5-tuple, in
// which case they are prioritized (from highest to lowest):
//  - connected socket exactly matching the local and remote address pair
//  - socket bound to the local address exactly
//  - socket bound to the any-address and the local port
//
// Returns NULL if no matching socket is found.
socket_tcp_t* tcpsm_find(const tcp_sockmap_t* sm,
                         const struct sockaddr_storage* local,
                         const struct sockaddr_storage* remote);

// Binds the socket in the socket map (has no external effect).  |local_addr| is
// required, though the address and/or the port may be ANY (e.g. 0.0.0.0 for
// ipv4, or port 0).  If |remote_addr| is not supplied, then this is a
// local-only binding, and effectively counts as a binding against _all_ remote
// addresses for matching purposes.
//
// If both local and remote addresses are given, then the local address cannot
// be the ANY-address (but can be the ANY-port); the remote address must always
// be fully specified.
//
// If the local port is zero and one is selected, the local address struct is
// updated accordingly.
//
// Returns 0 on succcess, or -error.
int tcpsm_bind(tcp_sockmap_t* sm, struct sockaddr_storage* local,
               const struct sockaddr_storage* remote, socket_tcp_t* sock);

// Removes the socket with the given local/remote address from the map.  The
// local and remote addresses must exactly match what was used by tcpsm_bind(),
// including the assigned port if any.
//
// The socket is passed for extra checking, it is not used actively.
int tcpsm_remove(tcp_sockmap_t* sm, const struct sockaddr_storage* local,
                 const struct sockaddr_storage* remote, socket_tcp_t* sock);

// Returns the number of connected sockets.
int tcpsm_num_connected(const tcp_sockmap_t* sm);

#endif
