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

#include <stddef.h>

#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/posix_types.h"

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

  // Shutdown the socket in one or both directions.
  int (*shutdown)(socket_t* socket, int how);

  // Bind the socket to a particular address.
  int (*bind)(socket_t* socket, const struct sockaddr* address,
              socklen_t address_len);

  // Start listening on the given socket.
  int (*listen)(socket_t* socket, int backlog);

  // Accept a connection on the given socket, returning the new peer socket in
  // |socket_out| on success.
  int (*accept)(socket_t* socket, int fflags, struct sockaddr* address,
                socklen_t* address_len, socket_t** socket_out);

  // Connect the socket to the given address.
  int (*connect)(socket_t* socket, int fflags, const struct sockaddr* address,
                 socklen_t address_len);

  // Returns the number of sockets queued on a listening socket.
  int (*accept_queue_length)(const socket_t* socket);

  // Receive data from the socket.
  ssize_t (*recvfrom)(socket_t* socket, int fflags, void* buffer, size_t length,
                      int sflags, struct sockaddr* address,
                      socklen_t* address_len);

  // Send data on the socket.
  ssize_t (*sendto)(socket_t* socket, int fflags, const void* message,
                    size_t length, int sflags, const struct sockaddr* dest_addr,
                    socklen_t dest_len);
};

// Creates a new unbound socket, per the POSIX socket() function.
int net_socket_create(int domain, int type, int protocol, socket_t** out);

// Cleans up (closing/shutting down if necessary) and frees the given socket.
void net_socket_destroy(socket_t* sock);

// Creates a new unbound socket and a new file descriptor pointing to it, per
// socket().  Returns the new fd or an error.
int net_socket(int domain, int type, int protocol);

// Shuts down the socket in one or both directions.
int net_shutdown(int socket, int how);

// Binds a socket to the given address.
int net_bind(int socket, const struct sockaddr* addr, socklen_t addr_len);

// Starts listening on the given socket.
int net_listen(int socket, int backlog);

// Accepts a connection on the given socket.
int net_accept(int socket, struct sockaddr* addr, socklen_t* addr_len);

// Connects a socket to the given address.
int net_connect(int socket, const struct sockaddr* addr, socklen_t addr_len);

// Returns the number of sockets queued on a listening socket.
int net_accept_queue_length(int socket);

// Receives data from the given socket.
ssize_t net_recv(int socket, void* buf, size_t len, int flags);
ssize_t net_recvfrom(int socket, void* buf, size_t len, int flags,
                     struct sockaddr* address, socklen_t* address_len);

// Sends data on the given socket.
ssize_t net_send(int socket, const void* buf, size_t len, int flags);
ssize_t net_sendto(int socket, const void* buf, size_t len, int flags,
                   const struct sockaddr* dest_addr, socklen_t dest_len);

#endif
