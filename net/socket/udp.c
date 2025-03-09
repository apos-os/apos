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

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/inet.h"
#include "net/ip/checksum.h"
#include "net/ip/ip.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/ip6.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/util.h"
#include "net/pbuf.h"
#include "net/socket/sockmap.h"
#include "net/util.h"
#include "proc/defint.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/vfs/vfs.h"

static const socket_ops_t g_udp_socket_ops;

// Lock for the global UDP sockmap and all UDP sockets.
// TODO(aoates): switch to per-socket locks.
static kspinlock_t g_udp_mu = KSPINLOCK_NORMAL_INIT_STATIC;

static const ip4_hdr_t* pb_ip4_hdr(const pbuf_t* pb) {
  return (const ip4_hdr_t*)pbuf_getc(pb);
}

static const ip6_hdr_t* pb_ip6_hdr(const pbuf_t* pb) {
  return (const ip6_hdr_t*)pbuf_getc(pb);
}

static const udp_hdr_t* pb_udp_hdr(const pbuf_t* pb, ssize_t ip_hdr_len) {
  return (const udp_hdr_t*)(pbuf_getc(pb) + ip_hdr_len);
}

static int sock_udp_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len);

static int bind_to_any(socket_udp_t* socket, const struct sockaddr* dst_addr) {
  KASSERT(dst_addr->sa_family == AF_UNSPEC ||
          dst_addr->sa_family == (addrfam_t)socket->base.s_domain);
  struct sockaddr_storage bind_addr;
  inet_make_anyaddr(socket->base.s_domain, (struct sockaddr*)&bind_addr);
  return sock_udp_bind(&socket->base, (struct sockaddr*)&bind_addr,
                       sizeof(bind_addr));
}

static short udp_poll_events(const socket_udp_t* socket) {
  short events = KPOLLOUT;
  KASSERT_DBG(!defint_state());
  if (!list_empty(&socket->rx_queue)) {
    events |= KPOLLIN;
  }
  return events;
}

int sock_udp_create(int domain, socket_t** out) {
  if (domain != AF_INET && domain != AF_INET6) {
    return -EAFNOSUPPORT;
  }

  socket_udp_t* sock = (socket_udp_t*)kmalloc(sizeof(socket_udp_t));
  if (!sock) return -ENOMEM;

  sock->base.s_domain = domain;
  sock->base.s_type = SOCK_DGRAM;
  sock->base.s_protocol = IPPROTO_UDP;
  sock->base.s_ops = &g_udp_socket_ops;

  sock->bind_addr.sa_family = AF_UNSPEC;
  sock->connected_addr.sa_family = AF_UNSPEC;
  sock->rx_queue = LIST_INIT;
  kthread_queue_init(&sock->wait_queue);
  poll_init_event(&sock->poll_event);

  *out = &(sock->base);
  return 0;
}

static bool check_inbound_ipv4(pbuf_t* pb, ssize_t header_len,
                               struct sockaddr_storage* src,
                               struct sockaddr_storage* dst) {
  // Validate the packet.
  KASSERT_DBG(pbuf_size(pb) >= sizeof(ip4_hdr_t));
  if (pbuf_size(pb) < sizeof(ip4_hdr_t) + sizeof(udp_hdr_t)) {
    klogfm(KL_NET, DEBUG, "net: dropping truncated UDP packet\n");
    return false;
  }
  const ip4_hdr_t* ip_hdr = pb_ip4_hdr(pb);
  const udp_hdr_t* udp_hdr = pb_udp_hdr(pb, header_len);
  KASSERT((size_t)header_len == ip4_ihl(*ip_hdr) * sizeof(uint32_t));
  KASSERT(header_len >= (ssize_t)sizeof(ip4_hdr_t));

  KASSERT_DBG(btoh16(ip_hdr->total_len) >=
              sizeof(ip4_hdr_t) + sizeof(udp_hdr_t));
  if (btoh16(udp_hdr->len) < sizeof(udp_hdr_t) ||
      btoh16(udp_hdr->len) > btoh16(ip_hdr->total_len) - header_len) {
    klogfm(KL_NET, DEBUG, "net: dropping UDP packet with invalid size\n");
    return false;
  }

  // Validate the checksum, if present.
  if (udp_hdr->checksum != 0) {
    ip4_pseudo_hdr_t pseudo_ip;
    pseudo_ip.src_addr = ip_hdr->src_addr;
    pseudo_ip.dst_addr = ip_hdr->dst_addr;
    pseudo_ip.zeroes = 0;
    pseudo_ip.protocol = IPPROTO_UDP;
    pseudo_ip.length = udp_hdr->len;

    KASSERT_DBG((ssize_t)pbuf_size(pb) >= btoh16(udp_hdr->len) + header_len);
    uint16_t checksum = ip_checksum2(&pseudo_ip, sizeof(pseudo_ip),
                                     /* really UDP header _and_ data */ udp_hdr,
                                     btoh16(udp_hdr->len));
    if (checksum != 0) {
      klogfm(KL_NET, DEBUG, "net: dropping UDP packet with bad checksum\n");
      return false;
    }
  }

  // Find a matching socket.
  struct sockaddr_in* src_addr = (struct sockaddr_in*)src;
  src_addr->sin_family = AF_INET;
  src_addr->sin_addr.s_addr = ip_hdr->src_addr;
  src_addr->sin_port = udp_hdr->src_port;

  struct sockaddr_in* dst_addr = (struct sockaddr_in*)dst;
  dst_addr->sin_family = AF_INET;
  dst_addr->sin_addr.s_addr = ip_hdr->dst_addr;
  dst_addr->sin_port = udp_hdr->dst_port;

  return true;
}

static bool check_inbound_ipv6(pbuf_t* pb, ssize_t header_len,
                               struct sockaddr_storage* src,
                               struct sockaddr_storage* dst) {
  // Validate the packet.
  KASSERT_DBG(pbuf_size(pb) >= sizeof(ip6_hdr_t));
  KASSERT_DBG((ssize_t)pbuf_size(pb) >= header_len);
  KASSERT_DBG(header_len >= (ssize_t)sizeof(ip6_hdr_t));
  const ip6_hdr_t* ip_hdr = (const ip6_hdr_t*)pbuf_getc(pb);

  // These should be enforced by the IP validation.
  KASSERT(btoh16(ip_hdr->payload_len) + header_len <= (ssize_t)pbuf_size(pb));
  if (btoh16(ip_hdr->payload_len) < sizeof(udp_hdr_t)) {
    klogfm(KL_NET, DEBUG, "net: dropping truncated UDP packet\n");
    return false;
  }
  const udp_hdr_t* udp_hdr = pb_udp_hdr(pb, header_len);
  if (btoh16(udp_hdr->len) < sizeof(udp_hdr_t) ||
      btoh16(udp_hdr->len) > pbuf_size(pb) - header_len) {
    klogfm(KL_NET, DEBUG, "net: dropping UDP packet with invalid size\n");
    return false;
  }

  // Validate the checksum, if present.
  if (udp_hdr->checksum != 0) {
    ip6_pseudo_hdr_t pseudo_ip;
    pseudo_ip.src_addr = ip_hdr->src_addr;
    pseudo_ip.dst_addr = ip_hdr->dst_addr;
    pseudo_ip.next_hdr = IPPROTO_UDP;
    pseudo_ip.payload_len = udp_hdr->len;
    kmemset(&pseudo_ip._zeroes, 0, 3);

    KASSERT_DBG((ssize_t)pbuf_size(pb) >= btoh16(udp_hdr->len) + header_len);
    uint16_t checksum = ip_checksum2(&pseudo_ip, sizeof(pseudo_ip),
                                     /* really UDP header _and_ data */ udp_hdr,
                                     btoh16(udp_hdr->len));
    if (checksum != 0) {
      klogfm(KL_NET, DEBUG, "net: dropping UDP packet with bad checksum\n");
      return false;
    }
  }

  // Find a matching socket.
  struct sockaddr_in6* src_addr = (struct sockaddr_in6*)src;
  src_addr->sin6_family = AF_INET6;
  src_addr->sin6_addr = ip_hdr->src_addr;
  src_addr->sin6_port = udp_hdr->src_port;

  struct sockaddr_in6* dst_addr = (struct sockaddr_in6*)dst;
  dst_addr->sin6_family = AF_INET6;
  dst_addr->sin6_addr = ip_hdr->dst_addr;
  dst_addr->sin6_port = udp_hdr->dst_port;

  return true;
}

bool sock_udp_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol,
                       ssize_t header_len) {
  KASSERT(protocol == IPPROTO_UDP);

  struct sockaddr_storage src_addr, dst_addr;
  if (ethertype == ET_IPV4) {
    if (!check_inbound_ipv4(pb, header_len, &src_addr, &dst_addr)) {
      return false;
    }
  } else {
    KASSERT(ethertype == ET_IPV6);
    if (!check_inbound_ipv6(pb, header_len, &src_addr, &dst_addr)) {
      return false;
    }
  }

  kspin_lock(&g_udp_mu);
  sockmap_t* sm = net_get_sockmap(dst_addr.sa_family, IPPROTO_UDP);
  socket_t* socket_base = sockmap_find(sm, (const struct sockaddr*)&dst_addr);
  if (!socket_base) {
    kspin_unlock(&g_udp_mu);
    return false;
  }

  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;

  // If the socket is connected, the source address must exactly match the
  // connected-to address.
  if (socket->connected_addr.sa_family != AF_UNSPEC) {
    if (!sockaddr_equal((struct sockaddr*)&socket->connected_addr,
                        (struct sockaddr*)&src_addr)) {
      kspin_unlock(&g_udp_mu);
      return false;
    }
  }

  // We own the pbuf now, add 4 bytes to store the header length.
  pbuf_push_header(pb, 4);
  uint32_t hl = header_len;
  kmemcpy(pbuf_get(pb), &hl, sizeof(hl));

  list_push(&socket->rx_queue, &pb->link);
  scheduler_wake_one(&socket->wait_queue);
  poll_trigger_event(&socket->poll_event, udp_poll_events(socket));

  kspin_unlock(&g_udp_mu);
  return true;
}

static void sock_udp_cleanup(socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_domain == AF_INET ||
              socket_base->s_domain == AF_INET6);
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_UDP);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    KASSERT_DBG(socket->bind_addr.sa_family ==
                (sa_family_t)socket_base->s_domain);
    kspin_lock(&g_udp_mu);
    sockmap_t* sm = net_get_sockmap(socket->bind_addr.sa_family, IPPROTO_UDP);
    socket_t* removed =
        sockmap_remove(sm, (struct sockaddr*)&socket->bind_addr);
    KASSERT(removed == socket_base);
    kspin_unlock(&g_udp_mu);
  }
  while (!list_empty(&socket->rx_queue)) {
    list_link_t* link = list_pop(&socket->rx_queue);
    pbuf_t* pb = container_of(link, pbuf_t, link);
    pbuf_free(pb);
  }
  KASSERT(kthread_queue_empty(&socket->wait_queue));
  // TODO(aoates): is this the proper way to handle this, or should vfs_poll()
  // retain a reference to the file containing this socket (and other pollables)
  // to ensure the file isn't destroyed while someone is polling it?
  poll_trigger_event(&socket->poll_event, KPOLLNVAL);
  poll_assert_empty_event(&socket->poll_event);
  kfree(socket);
}

static int sock_udp_shutdown(socket_t* socket_base, int how) {
  // N.B.(aoates): ostensibly we should check if the socket is connected, and
  // mark it as shutdown if so.  POSIX is ambiguous on if that's required,
  // though, so we take the lazy route.
  return -ENOTCONN;
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

  if ((addrfam_t)socket->base.s_domain != naddr.family) {
    return -EAFNOSUPPORT;
  }

  result = inet_bindable(&naddr);
  if (result) return result;

  kspin_lock(&g_udp_mu);
  sockmap_t* sm = net_get_sockmap(naddr.family, IPPROTO_UDP);
  if (naddr_port == 0) {
    in_port_t free_port = sockmap_free_port(sm, address);
    if (free_port == 0) {
      klogfm(KL_NET, WARNING, "net: out of ephemeral ports\n");
      kspin_unlock(&g_udp_mu);
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
  kspin_unlock(&g_udp_mu);
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
    result = bind_to_any(sock, address);
    if (result) return result;
  }

  kmemcpy(&sock->connected_addr, address, address_len);
  return 0;
}

static int sock_udp_accept_queue_length(const socket_t* socket_base) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  return -EOPNOTSUPP;
}

static ssize_t sock_udp_recvfrom(socket_t* socket_base, int fflags,
                                 void* buffer, size_t length, int sflags,
                                 struct sockaddr* address,
                                 socklen_t* address_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;

  kspin_lock(&g_udp_mu);
  while (list_empty(&socket->rx_queue)) {
    if (fflags & VFS_O_NONBLOCK) {
      kspin_unlock(&g_udp_mu);
      return -EAGAIN;
    }
    int result = scheduler_wait_on_splocked(&socket->wait_queue, -1, &g_udp_mu);
    if (result == SWAIT_INTERRUPTED) {
      kspin_unlock(&g_udp_mu);
      return -EINTR;
    }
  }

  // We have a packet!
  list_link_t* link = list_pop(&socket->rx_queue);
  kspin_unlock(&g_udp_mu);

  pbuf_t* pb = container_of(link, pbuf_t, link);
  uint32_t header_len;
  kmemcpy(&header_len, pbuf_getc(pb), sizeof(uint32_t));
  pbuf_pop_header(pb, 4);
  const udp_hdr_t* udp_hdr = pb_udp_hdr(pb, header_len);

  if (address && address_len) {
    struct sockaddr_storage src_addr;
    if (socket_base->s_domain == AF_INET) {
      struct sockaddr_in* src_addr_v4 = (struct sockaddr_in*)&src_addr;
      src_addr_v4->sin_family = AF_INET;
      src_addr_v4->sin_addr.s_addr = pb_ip4_hdr(pb)->src_addr;
      src_addr_v4->sin_port = udp_hdr->src_port;
    } else {
      KASSERT(socket_base->s_domain == AF_INET6);
      struct sockaddr_in6* src_addr_v6 = (struct sockaddr_in6*)&src_addr;
      src_addr_v6->sin6_family = AF_INET6;
      src_addr_v6->sin6_addr = pb_ip6_hdr(pb)->src_addr;
      src_addr_v6->sin6_port = udp_hdr->src_port;
      src_addr_v6->sin6_flowinfo = 0;
      src_addr_v6->sin6_scope_id = 0;
    }
    kmemcpy(address, &src_addr,
            min(sizeof_sockaddr(src_addr.sa_family), *address_len));
    *address_len = sizeof_sockaddr(src_addr.sa_family);
  }

  size_t bytes_to_copy = min(length, btoh16(udp_hdr->len) - sizeof(udp_hdr_t));
  kmemcpy(buffer, ((const char*)udp_hdr) + sizeof(udp_hdr_t), bytes_to_copy);
  pbuf_free(pb);
  return bytes_to_copy;
}

static ssize_t sock_udp_sendto(socket_t* socket_base, int fflags,
                               const void* buffer, size_t length, int sflags,
                               const struct sockaddr* dest_addr,
                               socklen_t dest_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;

  const struct sockaddr* actual_dst;
  socklen_t actual_dst_len;
  if (dest_addr) {
    if (socket->connected_addr.sa_family != AF_UNSPEC) {
      return -EISCONN;
    }
    actual_dst = dest_addr;
    actual_dst_len = dest_len;
    KASSERT(actual_dst_len >=
            (socklen_t)sizeof(sa_family_t));  // Checked by net_sendto()
    if (actual_dst->sa_family != (sa_family_t)socket_base->s_domain) {
      return -EAFNOSUPPORT;
    }
    if (dest_len < sizeof_sockaddr(actual_dst->sa_family)) {
      return -EINVAL;
    }
  } else if (socket->connected_addr.sa_family != AF_UNSPEC) {
    KASSERT_DBG(socket->connected_addr.sa_family == AF_INET ||
                socket->connected_addr.sa_family == AF_INET6);
    actual_dst = (struct sockaddr*)&socket->connected_addr;
    actual_dst_len = sizeof(struct sockaddr_storage);
  } else {
    return -EDESTADDRREQ;
  }
  dest_addr = NULL;
  dest_len = -1;

  // If we're unbound, bind to the any address.
  if (socket->bind_addr.sa_family == AF_UNSPEC) {
    int result = bind_to_any(socket, actual_dst);
    if (result) return result;
  }

  // Pick an IP to send from.
  struct sockaddr_storage* src = &socket->bind_addr;
  struct sockaddr_storage src_if_any;
  if (inet_is_anyaddr((struct sockaddr*)src)) {
    int result = ip_pick_src(actual_dst, actual_dst_len, &src_if_any);
    if (result) return result;
    src = &src_if_any;
    set_sockaddrs_port(src, get_sockaddrs_port(&socket->bind_addr));
  }

  // Actually generate and send the packet.
  pbuf_t* pb = pbuf_create(
      inet_header_reserve(socket_base->s_domain) + sizeof(udp_hdr_t), length);
  if (!pb) {
    return -ENOMEM;
  }

  // Copy data and build the UDP header (minus checksum).
  kmemcpy(pbuf_get(pb), buffer, length);
  pbuf_push_header(pb, sizeof(udp_hdr_t));
  udp_hdr_t* udp_hdr = (udp_hdr_t*)pbuf_get(pb);
  KASSERT_DBG(src->sa_family == (sa_family_t)socket_base->s_domain);
  KASSERT_DBG(actual_dst->sa_family == (sa_family_t)socket_base->s_domain);
  udp_hdr->src_port = btoh16(get_sockaddrs_port(src));
  udp_hdr->dst_port = btoh16(get_sockaddr_port(actual_dst, actual_dst_len));
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + length);
  udp_hdr->checksum = 0;

  if (socket_base->s_domain == AF_INET) {
    // Calculate the checksum.
    const struct sockaddr_in* src_v4 = (const struct sockaddr_in*)src;
    const struct sockaddr_in* dst_v4 = (const struct sockaddr_in*)actual_dst;
    ip4_pseudo_hdr_t pseudo_ip;
    pseudo_ip.src_addr = src_v4->sin_addr.s_addr;
    pseudo_ip.dst_addr = dst_v4->sin_addr.s_addr;
    pseudo_ip.zeroes = 0;
    pseudo_ip.protocol = IPPROTO_UDP;
    pseudo_ip.length = udp_hdr->len;

    udp_hdr->checksum =
        ip_checksum2(&pseudo_ip, sizeof(pseudo_ip), pbuf_get(pb), pbuf_size(pb));
    if (udp_hdr->checksum == 0) udp_hdr->checksum = 0xffff;

    ip4_add_hdr(pb, pseudo_ip.src_addr, pseudo_ip.dst_addr, IPPROTO_UDP);
    int result = ip_send(pb, /* allow_block */ true);
    if (result < 0) {
      return result;
    }
  } else {
    KASSERT(socket_base->s_domain == AF_INET6);
    // Calculate the checksum.
    const struct sockaddr_in6* src_v6 = (const struct sockaddr_in6*)src;
    const struct sockaddr_in6* dst_v6 = (const struct sockaddr_in6*)actual_dst;
    ip6_pseudo_hdr_t pseudo_ip;
    pseudo_ip.src_addr = src_v6->sin6_addr;
    pseudo_ip.dst_addr = dst_v6->sin6_addr;
    kmemset(&pseudo_ip._zeroes, 0, 3);
    pseudo_ip.next_hdr = IPPROTO_UDP;
    pseudo_ip.payload_len = htob32(btoh16(udp_hdr->len));

    udp_hdr->checksum = ip_checksum2(&pseudo_ip, sizeof(pseudo_ip),
                                     pbuf_get(pb), pbuf_size(pb));
    if (udp_hdr->checksum == 0) udp_hdr->checksum = 0xffff;

    ip6_add_hdr(pb, &pseudo_ip.src_addr, &pseudo_ip.dst_addr, IPPROTO_UDP, 0);
    int result = ip6_send(pb, /* allow_block */ true);
    if (result < 0) {
      return result;
    }
  }
  return length;
}

static int sock_udp_getsockname(socket_t* socket_base,
                                struct sockaddr_storage* address) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  if (socket->bind_addr.sa_family == AF_UNSPEC) {
    // We haven't bound yet.
    inet_make_anyaddr(socket_base->s_domain, (struct sockaddr*)address);
  } else {
    kmemcpy(address, &socket->bind_addr, sizeof(socket->bind_addr));
  }
  return sizeof_sockaddr(socket_base->s_domain);
}

static int sock_udp_getpeername(socket_t* socket_base,
                                struct sockaddr_storage* address) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;
  if (socket->connected_addr.sa_family == AF_UNSPEC) {
    return -ENOTCONN;
  }
  kmemcpy(address, &socket->connected_addr, sizeof(socket->connected_addr));
  return sizeof_sockaddr(socket_base->s_domain);
}

static int sock_udp_poll(socket_t* socket_base, short event_mask,
                         poll_state_t* poll) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  socket_udp_t* socket = (socket_udp_t*)socket_base;

  kspin_lock(&g_udp_mu);
  int result;
  const short masked_events = udp_poll_events(socket) & event_mask;
  if (masked_events || !poll) {
    result = masked_events;
  } else {
    result = poll_add_event(poll, &socket->poll_event, event_mask);
  }
  kspin_unlock(&g_udp_mu);
  return result;
}

static int sock_udp_getsockopt(socket_t* socket_base, int level, int option,
                                void* restrict val,
                                socklen_t* restrict val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_UDP);
  return -ENOPROTOOPT;
}

static int sock_udp_setsockopt(socket_t* socket_base, int level, int option,
                               const void* val, socklen_t val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_DGRAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_UDP);
  return -ENOPROTOOPT;
}

static const socket_ops_t g_udp_socket_ops = {
  &sock_udp_cleanup,
  &sock_udp_shutdown,
  &sock_udp_bind,
  &sock_udp_listen,
  &sock_udp_accept,
  &sock_udp_connect,
  &sock_udp_accept_queue_length,
  &sock_udp_recvfrom,
  &sock_udp_sendto,
  &sock_udp_getsockname,
  &sock_udp_getpeername,
  &sock_udp_poll,
  &sock_udp_getsockopt,
  &sock_udp_setsockopt,
};
