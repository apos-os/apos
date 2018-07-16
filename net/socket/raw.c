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
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "net/eth/ethertype.h"
#include "user/include/apos/net/socket/inet.h"

typedef struct {
  pbuf_t* pb;
  list_link_t link;
} queued_pkt_t;

static const socket_ops_t g_raw_socket_ops;

// Table of lists of raw sockets, indexed by (ethertype, protocol) pair.
static htbl_t g_raw_sockets;
static bool g_raw_sockets_init = false;

static void init_raw_sockets(void) {
  PUSH_AND_DISABLE_INTERRUPTS();
  if (!g_raw_sockets_init) {
    htbl_init(&g_raw_sockets, 10);
    g_raw_sockets_init = true;
  }
  POP_INTERRUPTS();
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

static void sock_raw_dispatch_one(socket_raw_t* sock, pbuf_t* pb) {
  KASSERT(g_raw_sockets_init);

  queued_pkt_t* qpkt = (queued_pkt_t*)kmalloc(sizeof(queued_pkt_t));
  KASSERT(qpkt != NULL);  // TODO(aoates): handle OOM?
  qpkt->link = LIST_LINK_INIT;
  qpkt->pb = pbuf_dup(pb, /* headers= */ false);
  KASSERT(qpkt->pb != NULL);  // TODO(aoates): handle OOM?

  list_push(&sock->rx_queue, &qpkt->link);

  // TODO(aoates): wake up any waiting threads and notify pollers.
}

void sock_raw_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol) {
  init_raw_sockets();

  PUSH_AND_DISABLE_INTERRUPTS();
  list_t* sock_list = get_socket_list(ethertype, protocol);
  list_link_t* link = sock_list->head;
  while (link) {
    socket_raw_t* sock = container_of(link, socket_raw_t, link);
    sock_raw_dispatch_one(sock, pb);
    link = link->next;
  }
  POP_INTERRUPTS();
}

int sock_raw_create(int domain, int type, int protocol, socket_t** out) {
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
  sock->base.s_type = type;
  sock->base.s_protocol = protocol;
  sock->base.s_ops = &g_raw_socket_ops;
  sock->rx_queue = LIST_INIT;
  sock->link = LIST_LINK_INIT;

  PUSH_AND_DISABLE_INTERRUPTS();
  KASSERT(domain == AF_INET);
  list_t* sock_list = get_socket_list(ET_IPV4, protocol);
  list_push(sock_list, &sock->link);
  sock->sock_list = sock_list;
  POP_INTERRUPTS();

  *out = &sock->base;
  return 0;
}

static void sock_raw_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_RAW);
  socket_raw_t* socket = (socket_raw_t*)socket_base;

  PUSH_AND_DISABLE_INTERRUPTS();
  list_remove(socket->sock_list, &socket->link);
  POP_INTERRUPTS();

  while (!list_empty(&socket->rx_queue)) {
    list_link_t* link = list_pop(&socket->rx_queue);
    queued_pkt_t* pkt = container_of(link, queued_pkt_t, link);
    pbuf_free(pkt->pb);
    kfree(pkt);
  }
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
