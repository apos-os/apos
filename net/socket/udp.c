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

#include "net/socket/udp.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/inet.h"
#include "net/socket/sockmap.h"
#include "net/util.h"
#include "user/include/apos/net/socket/inet.h"

static const socket_ops_t g_udp_socket_ops;

int sock_udp_create(socket_t** out) {
  socket_udp_t* sock = (socket_udp_t*)kmalloc(sizeof(socket_udp_t));
  if (!sock) return -ENOMEM;

  sock->base.s_domain = AF_INET;
  sock->base.s_type = SOCK_DGRAM;
  sock->base.s_protocol = IPPROTO_UDP;
  sock->base.s_ops = &g_udp_socket_ops;

  sock->bind_addr.sa_family = AF_UNSPEC;
  sock->connected_addr.sa_family = AF_UNSPEC;

  *out = &(sock->base);
  return 0;
}

static void sock_udp_cleanup(socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_domain == AF_INET);
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_UDP);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    KASSERT_DBG(socket->bind_addr.sa_family ==
                (sa_family_t)socket_base->s_domain);
    PUSH_AND_DISABLE_INTERRUPTS();
    sockmap_t* sm = net_get_sockmap(socket->bind_addr.sa_family, IPPROTO_UDP);
    socket_t* removed =
        sockmap_remove(sm, (struct sockaddr*)&socket->bind_addr);
    KASSERT(removed == socket_base);
    POP_INTERRUPTS();
  }
}

static int sock_udp_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    return -EINVAL;
  }

  netaddr_t naddr;
  int naddr_port;
  int result = sock2netaddr(address, address_len, &naddr, &naddr_port);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EADDRNOTAVAIL;

  result = inet_bindable(&naddr);
  if (result) return result;

  PUSH_AND_DISABLE_INTERRUPTS();
  sockmap_t* sm = net_get_sockmap(AF_INET, IPPROTO_UDP);
  if (naddr_port == 0) {
    in_port_t free_port = sockmap_free_port(sm, address);
    if (free_port == 0) {
      klogfm(KL_NET, WARNING, "net: out of ephemeral ports\n");
      POP_INTERRUPTS();
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
  POP_INTERRUPTS();
  if (!inserted) {
    return -EADDRINUSE;
  }

  kmemset(&socket->bind_addr, 0, sizeof(struct sockaddr_storage));
  kmemcpy(&socket->bind_addr, &addr_with_port, address_len);
  return 0;
}

static int sock_udp_listen(socket_t* socket_base, int backlog) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  return -EOPNOTSUPP;
}

static int sock_udp_accept(socket_t* socket_base, int fflags,
                           struct sockaddr* address, socklen_t* address_len,
                           socket_t** socket_out) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  return -EOPNOTSUPP;
}

static int sock_udp_connect(socket_t* socket_base, int fflags,
                            const struct sockaddr* address,
                            socklen_t address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* sock = (socket_udp_t*)socket_base;
  if (!address) return -EDESTADDRREQ;

  netaddr_t dest;
  int result = sock2netaddr(address, address_len, &dest, NULL);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EDESTADDRREQ;
  if (dest.family != AF_UNSPEC &&
      dest.family != (addrfam_t)sock->base.s_domain) {
    return -EAFNOSUPPORT;
  }

  // If we're unbound, bind to the any address.
  if (sock->bind_addr.sa_family == AF_UNSPEC) {
    KASSERT(address->sa_family == AF_INET);
    // TODO(aoates): make a generic make_any_addr() helper.
    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    result = sock_udp_bind(socket_base, (struct sockaddr*)&bind_addr,
                           sizeof(bind_addr));
    if (result) return result;
  }

  kmemcpy(&sock->connected_addr, address, address_len);
  return 0;
}

static int sock_udp_accept_queue_length(const socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  return -EOPNOTSUPP;
}

static int sock_udp_getsockname(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  kmemcpy(address, &socket->bind_addr, sizeof(socket->bind_addr));
  return 0;
}

static int sock_udp_getpeername(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  if (socket->connected_addr.sa_family == AF_UNSPEC) {
    return -ENOTCONN;
  }
  kmemcpy(address, &socket->connected_addr, sizeof(socket->connected_addr));
  return 0;
}

static const socket_ops_t g_udp_socket_ops = {
  &sock_udp_cleanup,
  NULL,
  &sock_udp_bind,
  &sock_udp_listen,
  &sock_udp_accept,
  &sock_udp_connect,
  &sock_udp_accept_queue_length,
  NULL,
  NULL,
  &sock_udp_getsockname,
  &sock_udp_getpeername,
  NULL,
};
