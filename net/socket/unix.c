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
  sock->bind_point = NULL;
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

  struct sockaddr_un* addr_un = (struct sockaddr_un*)address;
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
  return 0;
}

static const socket_ops_t g_unix_socket_ops = {
  &sock_unix_cleanup,
  &sock_unix_bind,
};
