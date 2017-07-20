// Copyright 2017 Andrew Oates.  All Rights Reserved.
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
#ifndef APOO_NET_SOCKET_SOCKET_H
#define APOO_NET_SOCKET_SOCKET_H

#include "user/include/apos/net/socket/socket.h"

struct socket_ops;
typedef struct socket_ops socket_ops_t;

// Base definition for all socket types.  Any socket type can be cast to a
// socket_t.
typedef struct {
  int s_domain;
  int s_type;
  int s_protocol;
  const socket_ops_t* s_ops;
} socket_t;

// Operations all socket types support.
struct socket_ops {
  // Clean up and free any underlying resources on the socket.
  // TODO(aoates): should this close the socket?
  void (*cleanup)(socket_t* socket);

  // Bind the socket to a particular address.
  int (*bind)(socket_t* socket, const struct sockaddr* address,
              socklen_t address_len);

  // Start listening on the given socket.
  int (*listen)(socket_t* socket, int backlog);

  // Accept a connection on the given socket, returning the new peer socket in
  // |socket_out| on success.
  // TODO(aoates): add blocking flag.
  int (*accept)(socket_t* socket, struct sockaddr* address,
                socklen_t* address_len, socket_t** socket_out);

  // Connect the socket to the given address.
  // TODO(aoates): add blocking flag.
  int (*connect)(socket_t* socket, const struct sockaddr* address,
                 socklen_t address_len);
};

// Creates a new unbound socket, per the POSIX socket() function.
int net_socket_create(int domain, int type, int protocol, socket_t** out);

// Cleans up (closing/shutting down if necessary) and frees the given socket.
void net_socket_destroy(socket_t* sock);

// Creates a new unbound socket and a new file descriptor pointing to it, per
// socket().  Returns the new fd or an error.
int net_socket(int domain, int type, int protocol);

// Binds a socket to the given address.
int net_bind(int socket, const struct sockaddr* addr, socklen_t addr_len);

// Starts listening on the given socket.
int net_listen(int socket, int backlog);

// Accepts a connection on the given socket.
int net_accept(int socket, struct sockaddr* addr, socklen_t* addr_len);

// Connects a socket to the given address.
int net_connect(int socket, const struct sockaddr* addr, socklen_t addr_len);

#endif
