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

#include "net/socket/raw.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "user/include/apos/net/socket/inet.h"

static const socket_ops_t g_raw_socket_ops;

int sock_raw_create(int domain, int type, int protocol, socket_t** out) {
  if (domain != AF_INET) {
    return -EPROTONOSUPPORT;
  }
  if (protocol == 0) {
    return -EPROTONOSUPPORT;
  }

  socket_raw_t* sock = (socket_raw_t*)kmalloc(sizeof(socket_raw_t));
  if (!sock) {
    return -ENOMEM;
  }

  sock->base.s_domain = domain;
  sock->base.s_type = type;
  sock->base.s_protocol = protocol;
  sock->base.s_ops = &g_raw_socket_ops;
  *out = &sock->base;
  return 0;
}

static void sock_raw_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_RAW);
}

static int sock_raw_shutdown(socket_t* socket_base, int how) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOTSUP;  // TODO(aoates): implement
}

static int sock_raw_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOTSUP;  // TODO(aoates): implement
}

static int sock_raw_listen(socket_t* socket_base, int backlog) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -EOPNOTSUPP;
}

static int sock_raw_accept(socket_t* socket_base, int fflags,
                           struct sockaddr* address, socklen_t* address_len,
                           socket_t** socket_out) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -EOPNOTSUPP;
}

static int sock_raw_connect(socket_t* socket_base, int fflags,
                            const struct sockaddr* address,
                            socklen_t address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -EOPNOTSUPP;
}

static int sock_raw_accept_queue_length(const socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -EOPNOTSUPP;
}

ssize_t sock_raw_recvfrom(socket_t* socket_base, int fflags, void* buffer,
                          size_t length, int sflags, struct sockaddr* address,
                          socklen_t* address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOTSUP;  // TODO(aoates): implement
}

ssize_t sock_raw_sendto(socket_t* socket_base, int fflags, const void* buffer,
                        size_t length, int sflags,
                        const struct sockaddr* dest_addr, socklen_t dest_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOTSUP;  // TODO(aoates): implement
}

static int sock_raw_poll(socket_t* socket_base, short event_mask,
                         poll_state_t* poll) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOTSUP;  // TODO(aoates): implement
}

static const socket_ops_t g_raw_socket_ops = {
  &sock_raw_cleanup,
  &sock_raw_shutdown,
  &sock_raw_bind,
  &sock_raw_listen,
  &sock_raw_accept,
  &sock_raw_connect,
  &sock_raw_accept_queue_length,
  &sock_raw_recvfrom,
  &sock_raw_sendto,
  &sock_raw_poll,
};
