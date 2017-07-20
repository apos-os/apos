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

// Unix domain sockets.
#ifndef APOO_NET_SOCKET_UNIX_H
#define APOO_NET_SOCKET_UNIX_H

#include "net/socket/socket.h"
#include "vfs/vnode.h"

typedef enum {
  SUN_UNCONNECTED,
  SUN_LISTENING,
  SUN_CONNECTING,
  SUN_CONNECTED,
} sockun_state_t;

typedef struct socket_unix {
  socket_t base;

  // Current state of the socket.
  sockun_state_t state;

  // The bind point of the socket, if its bound.
  vnode_t* bind_point;

  // If connected, our peer.
  struct socket_unix* peer;

  // Maximum connection backlog (if listening).
  int listen_backlog;

  // Sockets that are connecting to this (if listening).
  list_t incoming_conns;

  // Link on the destination socket's queue, if connecting.
  list_link_t connecting_link;
} socket_unix_t;

int sock_unix_create(int type, int protocol, socket_t** out);

#endif
