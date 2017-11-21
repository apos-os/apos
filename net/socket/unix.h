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
#include "proc/kthread.h"
#include "user/include/apos/net/socket/unix.h"
#include "vfs/vnode.h"

typedef enum {
  SUN_UNCONNECTED,
  SUN_LISTENING,
  SUN_CONNECTED,
} sockun_state_t;

typedef struct socket_unix {
  socket_t base;

  // Current state of the socket.
  sockun_state_t state;

  // The bind point of the socket, if its bound.
  vnode_t* bind_point;

  // The actual address we bound to, if any.
  struct sockaddr_un bind_address;

  // If connected, our peer.
  struct socket_unix* peer;

  // Maximum connection backlog (if listening).
  int listen_backlog;

  // If listening, new connection sockets to be returned by accept().
  list_t incoming_conns;

  // Thread queue to wait on for incoming connections.
  kthread_queue_t accept_wait_queue;

  // Link on the parent/server socket's queue, if an unaccepted connection.
  list_link_t connecting_link;

  // Data to be read.
  void* readbuf_raw;
  circbuf_t readbuf;
  bool read_fin;  // Has the other side shutdown or closed?
  // TODO(aoates): combine this with accept_wait_queue?
  kthread_queue_t read_wait_queue;  // Is there data in _our_ buffer?
  kthread_queue_t write_wait_queue;  // Is there room in _their_ buffer?
} socket_unix_t;

int sock_unix_create(int type, int protocol, socket_t** out);

#endif
