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
#include "net/socket/raw.h"
#include "net/socket/udp.h"
#include "net/socket/unix.h"
#include "vfs/anonfs.h"
#include "vfs/fsid.h"
#include "vfs/vfs_internal.h"

// Given a socket object, creates a new file descriptor for it.  On error, frees
// the socket object and returns an error.  In other words, after calling this,
// the caller should not touch the socket object either way.
static int create_socket_fd(socket_t* sock) {
  fs_t* const fs = g_fs_table[VFS_SOCKET_FS].fs;
  const kino_t socket_ino = anonfs_create_vnode(fs);

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

int net_socket_create(int domain, int type, int protocol, socket_t** out) {
  int result;
  // TODO(aoates): properly handle protocol parameter and generalize this.
  if (type == SOCK_RAW) {
    result = sock_raw_create(domain, protocol, out);
  } else if (domain == AF_UNIX) {
    result = sock_unix_create(type, protocol, out);
  } else if (domain == AF_INET) {
    if (type == SOCK_DGRAM) {
      if (protocol == 0 || protocol == IPPROTO_UDP) {
        result = sock_udp_create(out);
      } else {
        result = -EPROTONOSUPPORT;
      }
    } else {
      result = -EPROTOTYPE;
    }
  } else {
    result = -EAFNOSUPPORT;
  }
  if (result == 0) {
    KASSERT_DBG((*out)->s_domain == domain);
    KASSERT_DBG((*out)->s_type == type);
    KASSERT_DBG(protocol == 0 || protocol == (*out)->s_protocol);
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

  return create_socket_fd(sock);
}

int net_shutdown(int socket, int how) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result = file->vnode->socket->s_ops->shutdown(file->vnode->socket, how);
  file_unref(file);
  return result;
}

int net_bind(int socket, const struct sockaddr* addr, socklen_t addr_len) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result =
      file->vnode->socket->s_ops->bind(file->vnode->socket, addr, addr_len);
  file_unref(file);
  return result;
}

int net_listen(int socket, int backlog) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result = file->vnode->socket->s_ops->listen(file->vnode->socket, backlog);
  file_unref(file);
  return result;
}

int net_accept(int socket, struct sockaddr* addr, socklen_t* addr_len) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  socket_t* new_socket = NULL;
  result = file->vnode->socket->s_ops->accept(file->vnode->socket, file->flags,
                                              addr, addr_len, &new_socket);
  file_unref(file);
  if (result) {
    return result;
  }

  return create_socket_fd(new_socket);
}

int net_connect(int socket, const struct sockaddr* addr, socklen_t addr_len) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result = file->vnode->socket->s_ops->connect(file->vnode->socket, file->flags,
                                               addr, addr_len);
  file_unref(file);
  return result;
}

int net_accept_queue_length(int socket) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result = file->vnode->socket->s_ops->accept_queue_length(file->vnode->socket);
  file_unref(file);
  return result;
}

ssize_t net_recv(int socket, void* buf, size_t len, int flags) {
  return net_recvfrom(socket, buf, len, flags, NULL, 0);
}

ssize_t net_recvfrom(int socket, void* buf, size_t len, int flags,
                     struct sockaddr* address, socklen_t* address_len) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result = file->vnode->socket->s_ops->recvfrom(
      file->vnode->socket, file->flags, buf, len, flags, address, address_len);
  file_unref(file);
  return result;
}

ssize_t net_send(int socket, const void* buf, size_t len, int flags) {
  return net_sendto(socket, buf, len, flags, NULL, 0);
}

ssize_t net_sendto(int socket, const void* buf, size_t len, int flags,
                   const struct sockaddr* dest_addr, socklen_t dest_len) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result = file->vnode->socket->s_ops->sendto(
      file->vnode->socket, file->flags, buf, len, flags, dest_addr, dest_len);
  file_unref(file);
  return result;
}

int net_getsockname(int socket, struct sockaddr* address) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result =
      file->vnode->socket->s_ops->getsockname(file->vnode->socket, address);
  file_unref(file);
  return result;
}

int net_getpeername(int socket, struct sockaddr* address) {
  file_t* file = 0x0;
  int result = lookup_fd(socket, &file);
  if (result) return result;

  if (file->vnode->type != VNODE_SOCKET) {
    file_unref(file);
    return -ENOTSOCK;
  }

  KASSERT(file->vnode->socket != NULL);
  result =
      file->vnode->socket->s_ops->getpeername(file->vnode->socket, address);
  file_unref(file);
  return result;
}
