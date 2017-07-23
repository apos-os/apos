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

#include "net/socket/unix.h"

#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/unix.h"
#include "vfs/vfs_internal.h"

static const socket_ops_t g_unix_socket_ops;

int sock_unix_create(int type, int protocol, socket_t** out) {
  if (type != SOCK_STREAM) {
    return -EPROTOTYPE;
  } else if (protocol != 0) {
    return -EPROTONOSUPPORT;
  }

  socket_unix_t* sock = (socket_unix_t*)kmalloc(sizeof(socket_unix_t));
  if (!sock) {
    return -ENOMEM;
  }

  sock->base.s_domain = AF_UNIX;
  sock->base.s_type = type;
  sock->base.s_protocol = protocol;
  sock->base.s_ops = &g_unix_socket_ops;
  sock->state = SUN_UNCONNECTED;
  sock->bind_point = NULL;
  sock->bind_address.sun_path[0] = '\0';
  sock->peer = NULL;
  sock->listen_backlog = 0;
  sock->incoming_conns = LIST_INIT;
  sock->connecting_link = LIST_LINK_INIT;
  *out = &sock->base;
  return 0;
}

static void sock_unix_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  if (socket->bind_point) {
    KASSERT_DBG(socket->bind_point->type == VNODE_SOCKET);
    KASSERT_DBG(socket->bind_point->socket == NULL);
    KASSERT_DBG(socket->bind_point->bound_socket == socket_base);
    // TODO(aoates): find a way to test this by getting another reference to the
    // bind point vnode.
    socket->bind_point->bound_socket = NULL;
    VFS_PUT_AND_CLEAR(socket->bind_point);
  }
}

static int sock_unix_bind(socket_t* socket_base, const struct sockaddr* address,
                          socklen_t address_len) {
  if (address->sa_family != AF_UNIX) {
    return -EAFNOSUPPORT;
  }

  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  if (socket->bind_point != NULL) {
    return -EINVAL;
  }

  const struct sockaddr_un* addr_un = (const struct sockaddr_un*)address;
  if (kstrnlen(addr_un->sun_path,
               sizeof(struct sockaddr_un) - sizeof(sa_family_t)) < 0) {
    return -ENAMETOOLONG;
  }

  int result = vfs_mksocket(
      addr_un->sun_path, VFS_S_IFSOCK | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
      &socket->bind_point);
  if (result == -EEXIST) return -EADDRINUSE;
  else if (result) return result;

  socket->bind_point->bound_socket = socket_base;
  kmemcpy(&socket->bind_address, address, address_len);
  return 0;
}

static int sock_unix_listen(socket_t* socket_base, int backlog) {
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  if (socket->bind_point == NULL) {
    return -EDESTADDRREQ;
  } else if (socket->state != SUN_UNCONNECTED) {
    return -EINVAL;
  }

  socket->state = SUN_LISTENING;
  socket->listen_backlog = backlog;

  return 0;
}

static int sock_unix_accept(socket_t* socket_base, struct sockaddr* address,
                            socklen_t* address_len, socket_t** socket_out) {
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  // TODO(aoates): handle sockets in other states.
  KASSERT(socket->state == SUN_LISTENING);
  if (list_empty(&socket->incoming_conns)) {
    // TODO(aoates): block until connecting sockets are available.
    return -EWOULDBLOCK;
  }

  list_link_t* peer_link = list_pop(&socket->incoming_conns);
  socket_unix_t* peer = container_of(peer_link, socket_unix_t, connecting_link);
  int result = sock_unix_create(socket_base->s_type, socket_base->s_protocol,
                                socket_out);
  if (result) {
    return result;
  }

  socket_unix_t* new_socket = (socket_unix_t*)*socket_out;

  KASSERT_DBG(peer->state == SUN_CONNECTED);
  peer->peer = new_socket;
  new_socket->state = SUN_CONNECTED;
  new_socket->peer = peer;
  // TODO(aoates): should we set bind_point or the bound name?

  // TODO(aoates): check size of address
  if (address) {
    struct sockaddr_un* addr_un = (struct sockaddr_un*)address;
    addr_un->sun_family = AF_UNIX;
    *address_len = sizeof(struct sockaddr_un);
    if (peer->bind_point) {
      KASSERT_DBG(peer->bind_address.sun_family == AF_UNIX);
      kstrcpy(addr_un->sun_path, peer->bind_address.sun_path);
    } else {
      addr_un->sun_path[0] = '\0';
    }
  }

  return 0;
}

static int sock_unix_connect(socket_t* socket_base,
                             const struct sockaddr* address,
                             socklen_t address_len) {
  if (address->sa_family != AF_UNIX) {
    return -EAFNOSUPPORT;
  }

  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  switch (socket->state) {
    case SUN_UNCONNECTED:
      break;
    case SUN_LISTENING:
      return -EOPNOTSUPP;
    case SUN_CONNECTED:
      return -EISCONN;
  }

  const struct sockaddr_un* addr_un = (const struct sockaddr_un*)address;
  if (kstrnlen(addr_un->sun_path,
               sizeof(struct sockaddr_un) - sizeof(sa_family_t)) < 0) {
    return -ENAMETOOLONG;
  }

  vnode_t* target = NULL;
  int result =
      lookup_existing_path(addr_un->sun_path, lookup_opt(true), NULL, &target);
  if (result) {
    return result;
  }

  if (target->type != VNODE_SOCKET) {
    VFS_PUT_AND_CLEAR(target);
    return -ENOTSOCK;  // TODO(aoates): confirm this error is correct.
  }

  KASSERT_DBG(target->socket == NULL);
  if (target->bound_socket == NULL) {
    VFS_PUT_AND_CLEAR(target);
    return -ECONNREFUSED;
  }

  KASSERT_DBG(target->bound_socket->s_domain == AF_UNIX);
  socket_unix_t* target_sock = (socket_unix_t*)target->bound_socket;
  if (target_sock->state != SUN_LISTENING) {
    VFS_PUT_AND_CLEAR(target);
    return -ECONNREFUSED;
  }

  // TODO(aoates): check backlog length.
  list_push(&target_sock->incoming_conns, &socket->connecting_link);
  socket->state = SUN_CONNECTED;

  VFS_PUT_AND_CLEAR(target);
  return 0;
}

static const socket_ops_t g_unix_socket_ops = {
  &sock_unix_cleanup,
  &sock_unix_bind,
  &sock_unix_listen,
  &sock_unix_accept,
  &sock_unix_connect,
};
