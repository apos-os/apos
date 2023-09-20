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

#include "net/socket/tcp/socket.h"

#include "common/circbuf.h"
#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

#define DEFAULT_LISTEN_BACKLOG 10

// TODO(aoates): make this a socket option.
#define SOCKET_READBUF (16 * 1024)

static const socket_ops_t g_tcp_socket_ops;

int sock_tcp_create(int type, int protocol, socket_t** out) {
  if (type != SOCK_STREAM) {
    return -EPROTOTYPE;
  } else if (protocol != IPPROTO_TCP) {
    return -EPROTONOSUPPORT;
  }

  socket_tcp_t* sock = KMALLOC(socket_tcp_t);
  if (!sock) {
    return -ENOMEM;
  }

  void* rxbuf = kmalloc(SOCKET_READBUF);
  if (!rxbuf) {
    kfree(sock);
    return -ENOMEM;
  }

  sock->base.s_domain = AF_UNSPEC;
  sock->base.s_type = SOCK_STREAM;
  sock->base.s_protocol = IPPROTO_TCP;
  sock->base.s_ops = &g_tcp_socket_ops;

  sock->state = TCP_CLOSED;
  sock->bind_addr.sa_family = AF_UNSPEC;
  sock->connected_addr.sa_family = AF_UNSPEC;
  circbuf_init(&sock->rx_buf, rxbuf, SOCKET_READBUF);
  kthread_queue_init(&sock->wait_queue);
  poll_init_event(&sock->poll_event);

  *out = &(sock->base);
  return 0;
}

static void sock_tcp_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);
  // TODO(tcp): implement
  die("unimplemented");
}

static int sock_tcp_shutdown(socket_t* socket_base, int how) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_listen(socket_t* socket_base, int backlog) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_accept(socket_t* socket_base, int fflags,
                            struct sockaddr* address, socklen_t* address_len,
                            socket_t** socket_out) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_connect(socket_t* socket_base, int fflags,
                            const struct sockaddr* address,
                            socklen_t address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_accept_queue_length(const socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

ssize_t sock_tcp_recvfrom(socket_t* socket_base, int fflags, void* buffer,
                          size_t length, int sflags, struct sockaddr* address,
                          socklen_t* address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

ssize_t sock_tcp_sendto(socket_t* socket_base, int fflags, const void* buffer,
                        size_t length, int sflags,
                        const struct sockaddr* dest_addr, socklen_t dest_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_getsockname(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_getpeername(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_poll(socket_t* socket_base, short event_mask,
                         poll_state_t* poll) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static const socket_ops_t g_tcp_socket_ops = {
  &sock_tcp_cleanup,
  &sock_tcp_shutdown,
  &sock_tcp_bind,
  &sock_tcp_listen,
  &sock_tcp_accept,
  &sock_tcp_connect,
  &sock_tcp_accept_queue_length,
  &sock_tcp_recvfrom,
  &sock_tcp_sendto,
  &sock_tcp_getsockname,
  &sock_tcp_getpeername,
  &sock_tcp_poll,
};
