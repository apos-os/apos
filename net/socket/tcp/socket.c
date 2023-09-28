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
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/inet.h"
#include "net/util.h"
#include "net/socket/sockmap.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

#define DEFAULT_LISTEN_BACKLOG 10

// TODO(aoates): make this a socket option.
#define SOCKET_READBUF (16 * 1024)

static const socket_ops_t g_tcp_socket_ops;

int sock_tcp_create(int domain, int type, int protocol, socket_t** out) {
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

  sock->base.s_domain = domain;
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

static void tcp_finish_cleanup(socket_tcp_t* socket) {
  KASSERT(socket->state == TCP_CLOSED);

  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    KASSERT_DBG(socket->bind_addr.sa_family ==
                (sa_family_t)socket->base.s_domain);
    DEFINT_PUSH_AND_DISABLE();
    sockmap_t* sm = net_get_sockmap(socket->bind_addr.sa_family, IPPROTO_UDP);
    socket_t* removed =
        sockmap_remove(sm, (struct sockaddr*)&socket->bind_addr);
    KASSERT(removed == &socket->base);
    DEFINT_POP();
  }
  kfree(socket->rx_buf.buf);
  KASSERT(kthread_queue_empty(&socket->wait_queue));
  // TODO(aoates): is this the proper way to handle this, or should vfs_poll()
  // retain a reference to the file containing this socket (and other pollables)
  // to ensure the file isn't destroyed while someone is polling it?
  poll_trigger_event(&socket->poll_event, KPOLLNVAL);
  KASSERT(list_empty(&socket->poll_event.refs));
  kfree(socket);
}

static void sock_tcp_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;

  if (socket->state == TCP_CLOSED) {
    tcp_finish_cleanup(socket);
  } else {
    // TODO(tcp): close socket and defer cleanup after timeout.
    die("Cannot cleanup non-closed socket");
  }
}

static int sock_tcp_shutdown(socket_t* socket_base, int how) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

// TODO(aoates): this is almost exactly the same as UDP's bind; refactor/share?
static int sock_tcp_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);
  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    return -EINVAL;
  }

  // TODO(tcp): check for _connected_ sockets and fail if there are any bound to
  // the same address unless SO_REUSEADDR is set.

  netaddr_t naddr;
  int naddr_port;
  int result = sock2netaddr(address, address_len, &naddr, &naddr_port);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EADDRNOTAVAIL;

  result = inet_bindable(&naddr);
  if (result) return result;

  DEFINT_PUSH_AND_DISABLE();
  sockmap_t* sm = net_get_sockmap(AF_INET, IPPROTO_UDP);
  if (naddr_port == 0) {
    in_port_t free_port = sockmap_free_port(sm, address);
    if (free_port == 0) {
      klogfm(KL_NET, WARNING, "net: out of ephemeral ports\n");
      DEFINT_POP();
      return -EADDRINUSE;
    }
    naddr_port = free_port;
  }
  KASSERT_DBG(naddr_port >= INET_PORT_MIN);
  KASSERT_DBG(naddr_port <= INET_PORT_MAX);

  // TODO(aoates): check for permission to bind to low-numbered ports.

  struct sockaddr_storage addr_with_port;
  KASSERT(net2sockaddr(&naddr, naddr_port, &addr_with_port,
                       sizeof(addr_with_port)) == 0);
  bool inserted =
      sockmap_insert(sm, (struct sockaddr*)&addr_with_port, socket_base);
  DEFINT_POP();
  if (!inserted) {
    return -EADDRINUSE;
  }

  kmemset(&socket->bind_addr, 0, sizeof(struct sockaddr_storage));
  kmemcpy(&socket->bind_addr, &addr_with_port, address_len);
  return 0;
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

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  kmemcpy(address, &socket->bind_addr, sizeof(socket->bind_addr));
  return 0;
}

static int sock_tcp_getpeername(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  // TODO(tcp): check socket state as well
  if (socket->connected_addr.sa_family == AF_UNSPEC) {
    return -ENOTCONN;
  }
  kmemcpy(address, &socket->connected_addr, sizeof(socket->connected_addr));
  return 0;
}

static int sock_tcp_poll(socket_t* socket_base, short event_mask,
                         poll_state_t* poll) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_getsockopt(socket_t* socket_base, int level, int option,
                                void* restrict val,
                                socklen_t* restrict val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_STREAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_TCP);
  return -ENOPROTOOPT;
}

static int sock_tcp_setsockopt(socket_t* socket_base, int level, int option,
                               const void* val, socklen_t val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_STREAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_TCP);
  return -ENOPROTOOPT;
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
  &sock_tcp_getsockopt,
  &sock_tcp_setsockopt,
};
