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
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "net/bind.h"
#include "net/eth/ethertype.h"
#include "net/ip/ip.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/route.h"
#include "net/util.h"
#include "proc/defint.h"
#include "proc/scheduler.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/vfs/vfs.h"

typedef struct {
  pbuf_t* pb;
  struct sockaddr_storage src_addr;
  socklen_t src_addr_len;
  list_link_t link;
} queued_pkt_t;

static const socket_ops_t g_raw_socket_ops;

// Table of lists of raw sockets, indexed by (ethertype, protocol) pair.
static htbl_t g_raw_sockets;
static bool g_raw_sockets_init = false;

static void init_raw_sockets(void) {
  DEFINT_PUSH_AND_DISABLE();
  if (!g_raw_sockets_init) {
    htbl_init(&g_raw_sockets, 10);
    g_raw_sockets_init = true;
  }
  DEFINT_POP();
}

static list_t* get_socket_list(ethertype_t ethertype, int protocol) {
  KASSERT(g_raw_sockets_init);

  const uint32_t key = ((uint16_t)ethertype << 16) | (uint16_t)protocol;
  const uint32_t hash = fnv_hash(key);
  void* value = NULL;
  if (htbl_get(&g_raw_sockets, hash, &value) != 0) {
    value = kmalloc(sizeof(list_t));
    KASSERT(value != NULL);  // TODO(aoates): handle OOM?
    *((list_t*)value) = LIST_INIT;
    htbl_put(&g_raw_sockets, hash, value);
  }
  return (list_t*)value;
}

static short raw_poll_events(const socket_raw_t* socket) {
  short events = KPOLLOUT;
  KASSERT_DBG(!defint_state());
  if (!list_empty(&socket->rx_queue)) {
    events |= KPOLLIN;
  }
  return events;
}

static void sock_raw_dispatch_one(socket_raw_t* sock, pbuf_t* pb,
                                  const struct sockaddr* addr,
                                  socklen_t addrlen) {
  KASSERT(g_raw_sockets_init);

  queued_pkt_t* qpkt = (queued_pkt_t*)kmalloc(sizeof(queued_pkt_t));
  KASSERT(qpkt != NULL);  // TODO(aoates): handle OOM?
  qpkt->link = LIST_LINK_INIT;
  qpkt->pb = pbuf_dup(pb, /* headers= */ false);
  KASSERT(qpkt->pb != NULL);  // TODO(aoates): handle OOM?
  KASSERT_DBG(addrlen <= (long)sizeof(struct sockaddr_storage));
  kmemcpy(&qpkt->src_addr, addr, addrlen);
  qpkt->src_addr_len = addrlen;

  list_push(&sock->rx_queue, &qpkt->link);
  scheduler_wake_one(&sock->wait_queue);
  poll_trigger_event(&sock->poll_event, raw_poll_events(sock));
}

void sock_raw_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol,
                       const struct sockaddr* addr, socklen_t addrlen) {
  init_raw_sockets();

  DEFINT_PUSH_AND_DISABLE();
  list_t* sock_list = get_socket_list(ethertype, protocol);
  list_link_t* link = sock_list->head;
  while (link) {
    socket_raw_t* sock = container_of(link, socket_raw_t, link);
    sock_raw_dispatch_one(sock, pb, addr, addrlen);
    link = link->next;
  }
  DEFINT_POP();
}

int sock_raw_create(int domain, int protocol, socket_t** out) {
  init_raw_sockets();

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
  sock->base.s_type = SOCK_RAW;
  sock->base.s_protocol = protocol;
  sock->base.s_ops = &g_raw_socket_ops;
  sock->bind_addr.family = AF_UNSPEC;
  sock->connected_addr.family = AF_UNSPEC;
  sock->rx_queue = LIST_INIT;
  sock->link = LIST_LINK_INIT;
  kthread_queue_init(&sock->wait_queue);
  poll_init_event(&sock->poll_event);

  DEFINT_PUSH_AND_DISABLE();
  KASSERT(domain == AF_INET);
  list_t* sock_list = get_socket_list(ET_IPV4, protocol);
  list_push(sock_list, &sock->link);
  sock->sock_list = sock_list;
  DEFINT_POP();

  *out = &sock->base;
  return 0;
}

static void sock_raw_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_RAW);
  socket_raw_t* socket = (socket_raw_t*)socket_base;

  DEFINT_PUSH_AND_DISABLE();
  list_remove(socket->sock_list, &socket->link);
  DEFINT_POP();

  while (!list_empty(&socket->rx_queue)) {
    list_link_t* link = list_pop(&socket->rx_queue);
    queued_pkt_t* pkt = container_of(link, queued_pkt_t, link);
    pbuf_free(pkt->pb);
    kfree(pkt);
  }
  KASSERT_DBG(kthread_queue_empty(&socket->wait_queue));

  // Our socket is about to disappear.  Tell any pending poll()s as much.
  poll_trigger_event(&socket->poll_event, KPOLLNVAL);
  KASSERT(list_empty(&socket->poll_event.refs));
  kfree(socket);
}

static int sock_raw_shutdown(socket_t* socket_base, int how) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return 0;
}

static int sock_raw_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  socket_raw_t* socket = (socket_raw_t*)socket_base;
  if (socket->bind_addr.family != AF_UNSPEC) {
    return -EINVAL;
  }

  netaddr_t naddr;
  int result = sock2netaddr(address, address_len, &naddr, NULL);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EADDRNOTAVAIL;

  result = inet_bindable(&naddr);
  if (result) return result;

  socket->bind_addr = naddr;
  return 0;
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
  socket_raw_t* sock = (socket_raw_t*)socket_base;
  if (!address) return -EDESTADDRREQ;

  netaddr_t dest;
  int result = sock2netaddr(address, address_len, &dest, NULL);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EDESTADDRREQ;
  // TODO(aoates): add a way to test this:
  if (dest.family != (addrfam_t)sock->base.s_domain) return -EAFNOSUPPORT;

  if (sock->connected_addr.family != ADDR_UNSPEC) return -EISCONN;

  sock->connected_addr = dest;
  return 0;
}

static int sock_raw_accept_queue_length(const socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -EOPNOTSUPP;
}

ssize_t sock_raw_recvfrom(socket_t* socket_base, int fflags, void* buffer,
                          size_t length, int sflags, struct sockaddr* address,
                          socklen_t* address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  socket_raw_t* sock = (socket_raw_t*)socket_base;

  DEFINT_PUSH_AND_DISABLE();
  while (list_empty(&sock->rx_queue)) {
    if (fflags & VFS_O_NONBLOCK) {
      DEFINT_POP();
      return -EAGAIN;
    }
    int result = scheduler_wait_on_interruptable(&sock->wait_queue, -1);
    if (result == SWAIT_INTERRUPTED) {
      DEFINT_POP();
      return -EINTR;
    }
  }

  // We have a packet!
  list_link_t* link = list_pop(&sock->rx_queue);
  DEFINT_POP();

  queued_pkt_t* pkt = container_of(link, queued_pkt_t, link);
  if (address && address_len && *address_len >= pkt->src_addr_len) {
    kmemcpy(address, &pkt->src_addr, pkt->src_addr_len);
    *address_len = pkt->src_addr_len;
  }
  const ssize_t result = min(pbuf_size(pkt->pb), length);
  kmemcpy(buffer, pbuf_getc(pkt->pb), result);
  pbuf_free(pkt->pb);
  kfree(pkt);
  return result;
}

ssize_t sock_raw_sendto(socket_t* socket_base, int fflags, const void* buffer,
                        size_t length, int sflags,
                        const struct sockaddr* dest_addr, socklen_t dest_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  socket_raw_t* sock = (socket_raw_t*)socket_base;

  if (sock->base.s_domain != AF_INET) {
    // Shouldn't get here until we support other protocols anyways.
    return -EAFNOSUPPORT;
  }
  if (sflags != 0) {
    return -EINVAL;
  }
  netaddr_t dest;
  if (dest_addr) {
    if (sock->connected_addr.family != ADDR_UNSPEC) {
      return -EISCONN;
    }
    int result = sock2netaddr(dest_addr, dest_len, &dest, NULL);
    if (result) return result;

    if ((int)dest.family != sock->base.s_domain) {
      return -EAFNOSUPPORT;
    }
  } else if (sock->connected_addr.family != ADDR_UNSPEC) {
    KASSERT_DBG(sock->connected_addr.family == (addrfam_t)sock->base.s_domain);
    dest = sock->connected_addr;
  } else {
    return -EDESTADDRREQ;
  }

  // Pick a source address, either by using the bind address or doing a route
  // calculation.
  ip_routed_t route;
  const netaddr_t* src = NULL;
  if (sock->bind_addr.family != AF_UNSPEC) {
    KASSERT_DBG(sock->bind_addr.family == ADDR_INET);
    src = &sock->bind_addr;
  } else {
    if (!ip_route(dest, &route)) {
      return -ENETUNREACH;
    }
    src = &route.src;
  }

  // Actually generate and send the packet.
  pbuf_t* pb = pbuf_create(INET_HEADER_RESERVE, length);
  if (!pb) {
    return -ENOMEM;
  }

  kmemcpy(pbuf_get(pb), buffer, length);
  KASSERT_DBG(src->family == ADDR_INET);
  KASSERT_DBG(dest.family == ADDR_INET);
  ip4_add_hdr(pb, src->a.ip4.s_addr, dest.a.ip4.s_addr,
              socket_base->s_protocol);
  int result = ip_send(pb);
  if (result < 0) {
    return result;
  }
  return length;
}

static int sock_raw_getsockname(socket_t* socket_base,
                                struct sockaddr* address) {
  return -EOPNOTSUPP;
}

static int sock_raw_getpeername(socket_t* socket_base,
                                struct sockaddr* address) {
  return -EOPNOTSUPP;
}

static int sock_raw_poll(socket_t* socket_base, short event_mask,
                         poll_state_t* poll) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  socket_raw_t* sock = (socket_raw_t*)socket_base;

  DEFINT_PUSH_AND_DISABLE();
  int result;
  const short masked_events = raw_poll_events(sock) & event_mask;
  if (masked_events || !poll) {
    result = masked_events;
  } else {
    result = poll_add_event(poll, &sock->poll_event, event_mask);
  }
  DEFINT_POP();
  return result;
}

static int sock_raw_getsockopt(socket_t* socket_base, int level, int option,
                               void* val, socklen_t* val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOPROTOOPT;
}

static int sock_raw_setsockopt(socket_t* socket_base, int level, int option,
                               const void* val, socklen_t val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_RAW);
  return -ENOPROTOOPT;
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
  &sock_raw_getsockname,
  &sock_raw_getpeername,
  &sock_raw_poll,
  &sock_raw_getsockopt,
  &sock_raw_setsockopt,
};
