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

#ifndef APOO_NET_SOCKET_SOCKMAP_H
#define APOO_NET_SOCKET_SOCKMAP_H

#include <stdbool.h>

#include "common/list.h"
#include "net/socket/socket.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

// A socket map data structure.  Allows querying for sockets bound to particular
// IP addresses, including special handling of INADDR_ANY/wildcards.
typedef struct {
  sa_family_t family;
  // TODO(aoates): use a hash table instead of this list.
  list_t socks;
} sockmap_t;

// Creates a socket map.
sockmap_t* sockmap_create(sa_family_t family);

// Inserts an element into the socket map.  Returns true if successful, or false
// if there's a conflicting element already in the map (i.e. if sockmap_find()
// on the given address would succeed).
//
// The address's addr may be the ANY address (e.g. INADDR_ANY), but its port
// must be specified (cannot be zero).
bool sockmap_insert(sockmap_t* sm, const struct sockaddr* addr,
                    socket_t* socket);

// Returns the socket associated with the given address, or NULL.
//
// An entry will be returned if any of the following are true,
//  * e->addr == addr.addr && e->port == addr.port
//  * e->addr == ANY_ADDR && e->port == addr.port
//  * addr.arr == ANY_ADDR && e->port == addr.port
socket_t* sockmap_find(const sockmap_t* sm, const struct sockaddr* addr);

// Removes the socket with the given address from the map.  Unlike with
// sockmap_find(), the address and port must match exactly here (must equal what
// was passed to sockmap_insert()).
//
// Returns the socket that was removed, or NULL if none was found.
socket_t* sockmap_remove(sockmap_t* sm, const struct sockaddr* addr);

// Finds a free port for the given address in the sockmap and returns it.  That
// is, returns a port such that sockmap_find(sm, addr, <port>) would return
// NULL.  Ignores the port in the address.  Returns 0 if no port is available.
in_port_t sockmap_free_port(const sockmap_t* sm, const struct sockaddr* addr);

// Returns the global socket map associated with the given protocol and address
// family.
sockmap_t* net_get_sockmap(sa_family_t family, int protocol);

#endif
