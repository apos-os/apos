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
#include "net/socket/socket.h"

#include "common/kassert.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/vfs/vfs.h"
#include "net/socket/unix.h"
#include "vfs/anonfs.h"
#include "vfs/fsid.h"
#include "vfs/vfs_internal.h"

int net_socket_create(int domain, int type, int protocol, socket_t** out) {
  int result;
  if (domain == AF_UNIX) {
    result = sock_unix_create(type, protocol, out);
  } else {
    result = -EAFNOSUPPORT;
  }
  if (result == 0) {
    KASSERT_DBG((*out)->s_domain == domain);
    KASSERT_DBG((*out)->s_type == type);
    KASSERT_DBG((*out)->s_protocol == protocol);
  }
  return result;
}

void net_socket_destroy(socket_t* sock) {
  sock->s_ops->cleanup(sock);
  kfree(sock);
}

int net_socket(int domain, int type, int protocol) {
  socket_t* sock = NULL;
  int result = net_socket_create(domain, type, protocol, &sock);
  if (result) return result;

  fs_t* const fs = g_fs_table[VFS_SOCKET_FS].fs;
  const ino_t socket_ino = anonfs_create_vnode(fs);

  vnode_t* socket_vnode = vfs_get(fs, socket_ino);
  if (!socket_vnode) {
    kfree(sock);
    klogfm(KL_VFS, DFATAL, "vfs_get() on socket anonfs failed");
    return -EIO;
  }
  KASSERT_DBG(socket_vnode->type == VNODE_SOCKET);
  socket_vnode->socket = sock;

  int fd = vfs_open_vnode(socket_vnode, VFS_O_RDWR, false);
  VFS_PUT_AND_CLEAR(socket_vnode);
  return fd;
}

int net_bind(int socket, const struct sockaddr* addr, socklen_t addr_len) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    return -ENOTSOCK;
  }
  file->refcount++;

  KASSERT(file->vnode->socket != NULL);
  result =
      file->vnode->socket->s_ops->bind(file->vnode->socket, addr, addr_len);
  file->refcount--;
  return result;
}
