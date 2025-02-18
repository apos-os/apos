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
#include "common/math.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/unix.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/vfs_internal.h"

#define DEFAULT_LISTEN_BACKLOG 10

// TODO(aoates): make this a socket option.
#define SOCKET_READBUF (16 * 1024)

static const socket_ops_t g_unix_socket_ops;

// Global unix domain socket lock.
static kmutex_t g_unix_mu;

static short sun_poll_events(const socket_unix_t* socket) {
  kmutex_assert_is_held(&g_unix_mu);
  short events = 0;
  switch (socket->state) {
    case SUN_LISTENING:
      if (!list_empty(&socket->incoming_conns)) {
        events |= KPOLLIN | KPOLLRDNORM;
      }
      break;

    case SUN_CONNECTED:
      if (socket->readbuf.len > 0 || socket->read_fin) {
        events |= KPOLLIN | KPOLLRDNORM;
      }
      if (!socket->peer || socket->peer->read_fin) {
        // TODO(aoates): this may not be ideal---if the other side does a
        // shutdown(SHUT_RD), should we get a KPOLLHUP on our side?  KPOLLHUP is
        // impossible to mask, so we can't poll for readable data in that
        // scenario.
        events |= KPOLLHUP;
      } else if (socket->peer->readbuf.len < socket->peer->readbuf.buflen) {
        events |= KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND;
      }
      break;

    case SUN_UNCONNECTED:
      break;
  }
  return events;
}

static int sock_unix_create_locked(int type, int protocol, socket_t** out) {
  kmutex_assert_is_held(&g_unix_mu);
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
  sock->bind_address.sun_family = AF_UNIX;
  sock->bind_address.sun_path[0] = '\0';
  sock->peer = NULL;
  sock->listen_backlog = -1;
  sock->incoming_conns = LIST_INIT;
  kthread_queue_init(&sock->accept_wait_queue);
  sock->connecting_link = LIST_LINK_INIT;
  sock->readbuf_raw = 0x0;
  sock->read_fin = false;
  kthread_queue_init(&sock->read_wait_queue);
  kthread_queue_init(&sock->write_wait_queue);
  poll_init_event(&sock->poll_event);
  *out = &sock->base;
  return 0;
}

int sock_unix_create(int type, int protocol, socket_t** out) {
  kmutex_lock(&g_unix_mu);
  int result = sock_unix_create_locked(type, protocol, out);
  kmutex_unlock(&g_unix_mu);
  return result;
}

static void sock_unix_cleanup_locked(socket_t* socket_base) {
  kmutex_assert_is_held(&g_unix_mu);
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
  if (socket->peer) {
    KASSERT_DBG(socket->state == SUN_CONNECTED);
    KASSERT_DBG(socket->peer->state == SUN_CONNECTED);
    KASSERT_DBG(socket->peer->peer == socket);
    socket->peer->read_fin = true;
    scheduler_wake_all(&socket->peer->read_wait_queue);
    scheduler_wake_all(&socket->peer->write_wait_queue);
    socket->peer->peer = NULL;
    poll_trigger_event(&socket->peer->poll_event,
                       sun_poll_events(socket->peer));
    socket->peer = NULL;
  }
  if (!list_empty(&socket->incoming_conns)) {
    KASSERT_DBG(socket->state == SUN_LISTENING);
    while (!list_empty(&socket->incoming_conns)) {
      list_link_t* peer_link = list_pop(&socket->incoming_conns);
      socket_unix_t* incoming_socket =
          container_of(peer_link, socket_unix_t, connecting_link);
      sock_unix_cleanup_locked((socket_t*)incoming_socket);
    }
  }
  if (socket->readbuf_raw) {
    kfree(socket->readbuf_raw);
  }
  // We are cleaning up the socket, which means that any fds/files pointing to
  // it must have been closed.  So there must be no waiters.
  KASSERT_DBG(kthread_queue_empty(&socket->accept_wait_queue));
  KASSERT_DBG(kthread_queue_empty(&socket->read_wait_queue));
  KASSERT_DBG(kthread_queue_empty(&socket->write_wait_queue));

  // Our socket is about to disappear.  Tell any pending poll()s as much.
  poll_trigger_event(&socket->poll_event, KPOLLNVAL);
  KASSERT(list_empty(&socket->poll_event.refs));
  kfree(socket);
}

static void sock_unix_cleanup(socket_t* socket_base) {
  kmutex_lock(&g_unix_mu);
  sock_unix_cleanup_locked(socket_base);
  kmutex_unlock(&g_unix_mu);
}

static int sock_unix_shutdown(socket_t* socket_base, int how) {
  kmutex_lock(&g_unix_mu);
  if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR) {
    kmutex_unlock(&g_unix_mu);
    return -EINVAL;
  }

  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  if (socket->state != SUN_CONNECTED) {
    kmutex_unlock(&g_unix_mu);
    return -ENOTCONN;
  }

  if (how == SHUT_RD || how == SHUT_RDWR) {
    // read_fin is set if the peer is shutdown _or_ closed.
    if (socket->read_fin) {
      kmutex_unlock(&g_unix_mu);
      return -ENOTCONN;
    }
    // Throw away any pending data.
    socket->readbuf.len = 0;
    socket->read_fin = true;
    scheduler_wake_all(&socket->read_wait_queue);
    scheduler_wake_all(&socket->peer->write_wait_queue);
    poll_trigger_event(&socket->poll_event, sun_poll_events(socket));
    poll_trigger_event(&socket->peer->poll_event,
                       sun_poll_events(socket->peer));
  }
  if (how == SHUT_WR || how == SHUT_RDWR) {
    if (!socket->peer || socket->peer->read_fin) {
      kmutex_unlock(&g_unix_mu);
      return -ENOTCONN;
    }
    socket->peer->read_fin = true;
    scheduler_wake_all(&socket->peer->read_wait_queue);
    scheduler_wake_all(&socket->write_wait_queue);
    poll_trigger_event(&socket->poll_event, sun_poll_events(socket));
    poll_trigger_event(&socket->peer->poll_event,
                       sun_poll_events(socket->peer));
  }
  kmutex_unlock(&g_unix_mu);
  return 0;
}

static int sock_unix_bind(socket_t* socket_base, const struct sockaddr* address,
                          socklen_t address_len) {
  kmutex_lock(&g_unix_mu);
  if (address_len < (socklen_t)sizeof(struct sockaddr_un)) {
    kmutex_unlock(&g_unix_mu);
    return -EINVAL;
  }

  if (address->sa_family != AF_UNIX) {
    kmutex_unlock(&g_unix_mu);
    return -EAFNOSUPPORT;
  }

  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  if (socket->bind_point != NULL) {
    kmutex_unlock(&g_unix_mu);
    return -EINVAL;
  }

  const struct sockaddr_un* addr_un = (const struct sockaddr_un*)address;
  if (kstrnlen(addr_un->sun_path,
               sizeof(struct sockaddr_un) - sizeof(sa_family_t)) < 0) {
    kmutex_unlock(&g_unix_mu);
    return -ENAMETOOLONG;
  }

  int result = vfs_mksocket(
      addr_un->sun_path, VFS_S_IFSOCK | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
      &socket->bind_point);
  if (result == -EEXIST) {
    kmutex_unlock(&g_unix_mu);
    return -EADDRINUSE;
  } else if (result) {
    kmutex_unlock(&g_unix_mu);
    return result;
  }

  socket->bind_point->bound_socket = socket_base;
  kmemcpy(&socket->bind_address, address, address_len);
  kmutex_unlock(&g_unix_mu);
  return 0;
}

static int sock_unix_listen(socket_t* socket_base, int backlog) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  if (socket->bind_point == NULL) {
    kmutex_unlock(&g_unix_mu);
    return -EDESTADDRREQ;
  } else if (socket->state != SUN_UNCONNECTED) {
    kmutex_unlock(&g_unix_mu);
    return -EINVAL;
  }

  if (backlog <= 0) {
    backlog = DEFAULT_LISTEN_BACKLOG;
  } else if (backlog > SOMAXCONN) {
    backlog = SOMAXCONN;
  }

  socket->state = SUN_LISTENING;
  socket->listen_backlog = backlog;

  kmutex_unlock(&g_unix_mu);
  return 0;
}

static int sock_unix_accept(socket_t* socket_base, int fflags,
                            struct sockaddr* address, socklen_t* address_len,
                            socket_t** socket_out) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  if (socket->state != SUN_LISTENING) {
    kmutex_unlock(&g_unix_mu);
    return -EINVAL;
  }
  while (list_empty(&socket->incoming_conns)) {
    if (fflags & VFS_O_NONBLOCK) {
      kmutex_unlock(&g_unix_mu);
      return -EAGAIN;
    }
    int result =
        scheduler_wait_on_locked(&socket->accept_wait_queue, -1, &g_unix_mu);
    if (result == SWAIT_INTERRUPTED) {
      kmutex_unlock(&g_unix_mu);
      return -EINTR;
    }
  }

  list_link_t* new_socket_link = list_pop(&socket->incoming_conns);
  socket_unix_t* new_socket =
      container_of(new_socket_link, socket_unix_t, connecting_link);
  *socket_out = (socket_t*)new_socket;

  KASSERT_DBG(new_socket->state == SUN_CONNECTED);
  if (new_socket->peer) {
    KASSERT_DBG(new_socket->peer->state == SUN_CONNECTED);
    KASSERT_DBG(new_socket->peer->peer == new_socket);
  }

  if (address && address_len) {
    const int max_path_len =
        *address_len - (int)offsetof(struct sockaddr_un, sun_path) - 1;
    *address_len = sizeof(struct sockaddr_un);
    if (max_path_len > 0) {
      struct sockaddr_un* addr_un = (struct sockaddr_un*)address;
      addr_un->sun_family = AF_UNIX;
      const socket_unix_t* peer = new_socket->peer;
      if (peer && peer->bind_point) {
        KASSERT_DBG(peer->bind_address.sun_family == AF_UNIX);
        kstrncpy(addr_un->sun_path, peer->bind_address.sun_path, max_path_len);
        addr_un->sun_path[max_path_len] = '\0';
      } else {
        addr_un->sun_path[0] = '\0';
      }
    }
  }
  socket->listen_backlog++;

  kmutex_unlock(&g_unix_mu);
  return 0;
}

static int sock_unix_connect(socket_t* socket_base, int fflags,
                             const struct sockaddr* address,
                             socklen_t address_len) {
  kmutex_lock(&g_unix_mu);
  if (address->sa_family != AF_UNIX) {
    kmutex_unlock(&g_unix_mu);
    return -EAFNOSUPPORT;
  }

  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  switch (socket->state) {
    case SUN_UNCONNECTED:
      break;
    case SUN_LISTENING:
      kmutex_unlock(&g_unix_mu);
      return -EOPNOTSUPP;
    case SUN_CONNECTED:
      kmutex_unlock(&g_unix_mu);
      return -EISCONN;
  }

  const struct sockaddr_un* addr_un = (const struct sockaddr_un*)address;
  if (kstrnlen(addr_un->sun_path,
               sizeof(struct sockaddr_un) - sizeof(sa_family_t)) < 0) {
    kmutex_unlock(&g_unix_mu);
    return -ENAMETOOLONG;
  }

  vnode_t* target = NULL;
  int result =
      lookup_existing_path(addr_un->sun_path, lookup_opt(true), &target);
  if (result) {
    kmutex_unlock(&g_unix_mu);
    return result;
  }

  if (target->type != VNODE_SOCKET) {
    VFS_PUT_AND_CLEAR(target);
    kmutex_unlock(&g_unix_mu);
    return -ENOTSOCK;
  }

  KASSERT_DBG(target->socket == NULL);
  if (target->bound_socket == NULL) {
    VFS_PUT_AND_CLEAR(target);
    kmutex_unlock(&g_unix_mu);
    return -ECONNREFUSED;
  }

  KASSERT_DBG(target->bound_socket->s_domain == AF_UNIX);
  socket_unix_t* target_sock = (socket_unix_t*)target->bound_socket;
  VFS_PUT_AND_CLEAR(target);
  if (target_sock->state != SUN_LISTENING) {
    kmutex_unlock(&g_unix_mu);
    return -ECONNREFUSED;
  }

  KASSERT_DBG(target_sock->listen_backlog >= 0);
  if (target_sock->listen_backlog == 0) {
    kmutex_unlock(&g_unix_mu);
    return -ECONNREFUSED;
  }

  // Create the new peer socket.
  socket_t* new_socket_base = NULL;
  result = sock_unix_create_locked(socket_base->s_type, socket_base->s_protocol,
                                   &new_socket_base);
  if (result) {
    kmutex_unlock(&g_unix_mu);
    return result;
  }

  socket_unix_t* new_socket = (socket_unix_t*)new_socket_base;
  new_socket->state = SUN_CONNECTED;
  new_socket->peer = socket;
  new_socket->readbuf_raw = kmalloc(SOCKET_READBUF);
  circbuf_init(&new_socket->readbuf, new_socket->readbuf_raw, SOCKET_READBUF);
  kmemcpy(&new_socket->bind_address, &target_sock->bind_address,
          sizeof(struct sockaddr_un));
  // TODO(aoates): should we set bind_point?

  list_push(&target_sock->incoming_conns, &new_socket->connecting_link);
  target_sock->listen_backlog--;
  socket->peer = new_socket;
  socket->state = SUN_CONNECTED;
  socket->readbuf_raw = kmalloc(SOCKET_READBUF);
  circbuf_init(&socket->readbuf, socket->readbuf_raw, SOCKET_READBUF);
  scheduler_wake_all(&target_sock->accept_wait_queue);
  poll_trigger_event(&target_sock->poll_event, sun_poll_events(target_sock));

  kmutex_unlock(&g_unix_mu);
  return 0;
}

static int sock_unix_accept_queue_length(const socket_t* socket_base) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;
  int result = list_size(&socket->incoming_conns);
  kmutex_unlock(&g_unix_mu);
  return result;
}

ssize_t sock_unix_recvfrom(socket_t* socket_base, int fflags, void* buffer,
                           size_t length, int sflags, struct sockaddr* address,
                           socklen_t* address_len) {
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  if (!buffer || sflags != 0) {
    return -EINVAL;
  }

  kmutex_lock(&g_unix_mu);
  if (socket->state != SUN_CONNECTED) {
    kmutex_unlock(&g_unix_mu);
    return -ENOTCONN;
  }
  KASSERT_DBG(socket->readbuf_raw != 0x0);

  while (socket->readbuf.len == 0 && !socket->read_fin) {
    if (fflags & VFS_O_NONBLOCK) {
      kmutex_unlock(&g_unix_mu);
      return -EAGAIN;
    }
    int result =
        scheduler_wait_on_locked(&socket->read_wait_queue, -1, &g_unix_mu);
    if (result == SWAIT_INTERRUPTED) {
      kmutex_unlock(&g_unix_mu);
      return -EINTR;
    }
  }

  int result = circbuf_read(&socket->readbuf, buffer, length);
  if (socket->peer) {
    scheduler_wake_all(&socket->peer->write_wait_queue);
    poll_trigger_event(&socket->peer->poll_event,
                       sun_poll_events(socket->peer));
  }

  if (address_len) {
    // Not required to set the address for SOCK_STREAM sockets.
    *address_len = 0;
  }

  kmutex_unlock(&g_unix_mu);
  return result;
}

ssize_t sock_unix_sendto(socket_t* socket_base, int fflags, const void* buffer,
                         size_t length, int sflags,
                         const struct sockaddr* dest_addr, socklen_t dest_len) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  if (!buffer || sflags != 0) {
    kmutex_unlock(&g_unix_mu);
    return -EINVAL;
  }

  if (socket->state != SUN_CONNECTED) {
    kmutex_unlock(&g_unix_mu);
    return -ENOTCONN;
  }

  if (socket->peer) KASSERT(socket->peer->readbuf_raw != 0x0);
  while (socket->peer &&
         socket->peer->readbuf.buflen - socket->peer->readbuf.len == 0 &&
         !socket->peer->read_fin) {
    if (fflags & VFS_O_NONBLOCK) {
      kmutex_unlock(&g_unix_mu);
      return -EAGAIN;
    }
    int result =
        scheduler_wait_on_locked(&socket->write_wait_queue, -1, &g_unix_mu);
    if (result == SWAIT_INTERRUPTED) {
      kmutex_unlock(&g_unix_mu);
      return -EINTR;
    }
  }
  if (socket->peer == 0x0 || socket->peer->read_fin) {
    proc_force_signal(proc_current(), SIGPIPE);
    kmutex_unlock(&g_unix_mu);
    return -EPIPE;
  }

  int result = circbuf_write(&socket->peer->readbuf, buffer, length);
  scheduler_wake_all(&socket->peer->read_wait_queue);
  poll_trigger_event(&socket->peer->poll_event, sun_poll_events(socket->peer));
  kmutex_unlock(&g_unix_mu);
  return result;
}

static int sock_unix_getsockname(socket_t* socket_base,
                                 struct sockaddr_storage* address) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  kmemcpy(address, &socket->bind_address, sizeof(struct sockaddr_un));
  kmutex_unlock(&g_unix_mu);
  return sizeof(struct sockaddr_un);
}

static int sock_unix_getpeername(socket_t* socket_base,
                                 struct sockaddr_storage* address) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  if (!socket->peer) {
    kmutex_unlock(&g_unix_mu);
    return -ENOTCONN;
  }

  kmemcpy(address, &socket->peer->bind_address, sizeof(struct sockaddr_un));
  kmutex_unlock(&g_unix_mu);
  return sizeof(struct sockaddr_un);
}

static int sock_unix_poll(socket_t* socket_base, short event_mask,
                          poll_state_t* poll) {
  kmutex_lock(&g_unix_mu);
  KASSERT(socket_base->s_domain == AF_UNIX);
  socket_unix_t* const socket = (socket_unix_t*)socket_base;

  const short masked_events = sun_poll_events(socket) & event_mask;
  if (masked_events || !poll) {
    kmutex_unlock(&g_unix_mu);
    return masked_events;
  }

  int result = poll_add_event(poll, &socket->poll_event, event_mask);
  kmutex_unlock(&g_unix_mu);
  return result;
}

static int sock_unix_getsockopt(socket_t* socket_base, int level, int option,
                                void* val, socklen_t* val_len) {
  return -ENOPROTOOPT;
}

static int sock_unix_setsockopt(socket_t* socket_base, int level, int option,
                                const void* val, socklen_t val_len) {
  KASSERT_DBG(socket_base->s_domain == AF_UNIX);
  return -ENOPROTOOPT;
}

static const socket_ops_t g_unix_socket_ops = {
  &sock_unix_cleanup,
  &sock_unix_shutdown,
  &sock_unix_bind,
  &sock_unix_listen,
  &sock_unix_accept,
  &sock_unix_connect,
  &sock_unix_accept_queue_length,
  &sock_unix_recvfrom,
  &sock_unix_sendto,
  &sock_unix_getsockname,
  &sock_unix_getpeername,
  &sock_unix_poll,
  &sock_unix_getsockopt,
  &sock_unix_setsockopt,
};
