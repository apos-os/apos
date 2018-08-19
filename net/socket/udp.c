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
#include "memory/kmalloc.h"
#include "user/include/apos/net/socket/inet.h"

static const socket_ops_t g_udp_socket_ops;

int sock_udp_create(socket_t** out) {
  socket_udp_t* sock = (socket_udp_t*)kmalloc(sizeof(socket_udp_t));
  if (!sock) return -ENOMEM;

  sock->base.s_domain = AF_INET;
  sock->base.s_type = SOCK_DGRAM;
  sock->base.s_protocol = IPPROTO_UDP;
  sock->base.s_ops = &g_udp_socket_ops;

  *out = &(sock->base);
  return 0;
}

static void sock_udp_cleanup(socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_domain == AF_INET);
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
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

static int sock_udp_accept_queue_length(const socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  return -EOPNOTSUPP;
}

static const socket_ops_t g_udp_socket_ops = {
  &sock_udp_cleanup,
  NULL,
  NULL,
  &sock_udp_listen,
  &sock_udp_accept,
  NULL,
  &sock_udp_accept_queue_length,
  NULL,
  NULL,
  NULL,
};
