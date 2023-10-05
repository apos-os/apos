// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#include "net/socket/tcp/socket.h"

#include "common/circbuf.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/refcount.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/eth/ethertype.h"
#include "net/inet.h"
#include "net/ip/util.h"
#include "net/pbuf.h"
#include "net/socket/sockmap.h"
#include "net/socket/sockopt.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/protocol.h"
#include "net/socket/tcp/tcp.h"
#include "net/util.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/tcp.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

#define DEFAULT_LISTEN_BACKLOG 10

// TODO(aoates): make this a socket option.
#define SOCKET_READBUF (16 * 1024)

// TODO(tcp): make this a socket option
// TODO(tcp): increase this default
#define SOCKET_CONNECT_TIMEOUT_MS 1000

static const socket_ops_t g_tcp_socket_ops;

static uint32_t gen_seq_num(const socket_tcp_t* sock) {
  return fnv_hash_concat(get_time_ms(), fnv_hash_addr((addr_t)sock));
}

int sock_tcp_create(int domain, int type, int protocol, socket_t** out) {
  if (type != SOCK_STREAM) {
    return -EPROTOTYPE;
  } else if (protocol != IPPROTO_TCP) {
    return -EPROTONOSUPPORT;
  }

  socket_tcp_t* sock = KMALLOC(socket_tcp_t);
  if (!sock) {
    return -ENOMEM;
  }

  void* rxbuf = kmalloc(SOCKET_READBUF);
  if (!rxbuf) {
    kfree(sock);
    return -ENOMEM;
  }

  sock->base.s_domain = domain;
  sock->base.s_type = SOCK_STREAM;
  sock->base.s_protocol = IPPROTO_TCP;
  sock->base.s_ops = &g_tcp_socket_ops;

  sock->state = TCP_CLOSED;
  sock->error = 0;
  sock->ref = REFCOUNT_INIT;
  sock->bind_addr.sa_family = AF_UNSPEC;
  sock->connected_addr.sa_family = AF_UNSPEC;
  circbuf_init(&sock->rx_buf, rxbuf, SOCKET_READBUF);
  sock->seq = gen_seq_num(sock);
  sock->wndsize = circbuf_available(&sock->rx_buf);
  kthread_queue_init(&sock->q);
  kmutex_init(&sock->mu);
  sock->spin_mu = KSPINLOCK_NORMAL_INIT;
  poll_init_event(&sock->poll_event);

  *out = &(sock->base);
  return 0;
}

socktcp_state_type_t get_state_type(socktcp_state_t s) {
  switch (s) {
    case TCP_CLOSED:
    case TCP_SYN_SENT:
      return TCPSTATE_PRE_ESTABLISHED;

    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
      return TCPSTATE_ESTABLISHED;

    case TCP_LAST_ACK:
    case TCP_CLOSED_DONE:
      return TCPSTATE_POST_ESTABLISHED;
  }
  KLOG(DFATAL, "TCP: invalid socket state %d\n", (int)s);
  return TCPSTATE_POST_ESTABLISHED;
}

static inline const char* state2str(socktcp_state_t state) {
#define CONSIDER(X) case TCP_##X: return #X;
  switch (state) {
    CONSIDER(CLOSED)
    CONSIDER(CLOSED_DONE)
    CONSIDER(SYN_SENT)
    CONSIDER(ESTABLISHED)
    CONSIDER(CLOSE_WAIT)
    CONSIDER(LAST_ACK)
  }
#undef CONSIDER
  KLOG(FATAL, "Unknown TCP state %d\n", state);
  return "UNKNOWN";
}

static void set_state(socket_tcp_t* sock, socktcp_state_t new_state,
                      const char* debug_msg) {
  KASSERT(kspin_is_held(&sock->spin_mu));
  KLOG(DEBUG2, "TCP: socket %p state %s -> %s (%s)\n", sock,
       state2str(sock->state), state2str(new_state), debug_msg);
  sock->state = new_state;
  // Wake up anyone waiting for a state transition.
  scheduler_wake_all(&sock->q);
}

static void delete_socket(socket_tcp_t* socket) {
  kfree(socket->rx_buf.buf);
  kfree(socket);
}

#define TCP_DEC_REFCOUNT(_socket_var)             \
  do {                                            \
    if (refcount_dec(&(_socket_var)->ref) == 0) { \
      delete_socket(_socket_var);                 \
    }                                             \
    _socket_var = NULL;                           \
  } while (0)

// Helper to determine if we're currently in a particular state without having
// the spinlock held.  Only some states can be checked "racily" --- states that
// if the socket is in, deferred interrupts will never transition out of (only
// other kernel threads).  Rather than sprinkle that logic around, encapsulate
// the nuanced safety constraint here.
// TODO(tcp): given we can receive a RST at any point, can anything other than
// CLOSED or CLOSED_DONE actually be safe here?
static bool is_in_state(socket_tcp_t* sock, socktcp_state_t target_state) {
  kmutex_assert_is_held(&sock->mu);
  // Must be checking a "stable" state.
  KASSERT_DBG(target_state == TCP_CLOSED || target_state == TCP_CLOSED_DONE);
  kspin_lock(&sock->spin_mu);
  bool result = (sock->state == target_state);
  kspin_unlock(&sock->spin_mu);
  return result;
}

static void clear_addr(struct sockaddr_storage* addr) {
  kmemset(addr, 0xab, sizeof(struct sockaddr_storage));
  addr->sa_family = AF_UNSPEC;
}

static int sock_tcp_bind_locked(socket_tcp_t* socket,
                                const struct sockaddr* address,
                                socklen_t address_len, bool allow_rebind);

// If the given socket is unbound or is bound to the ANY address, pick a source
// IP and bind it (with an ephemeral port).
static int bind_if_necessary(socket_tcp_t* socket,
                             const struct sockaddr* dst_addr,
                             socklen_t dst_len) {
  kmutex_assert_is_held(&socket->mu);
  if (socket->bind_addr.sa_family != AF_UNSPEC &&
      !inet_is_anyaddr((const struct sockaddr*)&socket->bind_addr)) {
    return 0;
  }

  struct sockaddr_storage addr_to_bind;
  int result = ip_pick_src(dst_addr, dst_len, &addr_to_bind);
  if (result) return result;

  // If there is currently a bound port, copy it to the new address.
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    in_port_t bound_port = get_sockaddrs_port(&socket->bind_addr);
    KASSERT(bound_port != 0);  // Should never have a bound IP but not a port.
    set_sockaddrs_port(&addr_to_bind, bound_port);

    char buf[INET_PRETTY_LEN];
    KLOG(DEBUG2, "TCP: socket %p used bound port for new address %s\n", socket,
         sockaddr2str((const struct sockaddr*)&addr_to_bind,
                      sizeof(addr_to_bind), buf));
  }

  return sock_tcp_bind_locked(socket, (struct sockaddr*)&addr_to_bind,
                              sizeof(addr_to_bind),
                              /* allow_rebind = */ true);
}

static bool tcp_dispatch_to_sock(socket_tcp_t* socket, pbuf_t* pb);

bool sock_tcp_dispatch(pbuf_t* pb, ethertype_t ethertype, int protocol) {
  KASSERT_DBG(ethertype == ET_IPV4);
  KASSERT_DBG(protocol == IPPROTO_TCP);

  // Validate the packet.
  tcp_packet_metadata_t mdata;
  if (!tcp_validate_packet(pb, &mdata)) {
    // Drop the packet if it is TCP but invalid.
    pbuf_free(pb);
    return true;
  }

  // Find a matching socket --- first check connected sockets.
  tcp_key_t tcpkey =
      tcp_key((struct sockaddr*)&mdata.dst, (struct sockaddr*)&mdata.src);
  kspin_lock(&g_tcp.lock);
  void* val;
  if (htbl_get(&g_tcp.connected_sockets, tcpkey, &val) == 0) {
    socket_tcp_t* socket = (socket_tcp_t*)val;
    refcount_inc(&socket->ref);
    kspin_unlock(&g_tcp.lock);
    bool result = tcp_dispatch_to_sock(socket, pb);
    TCP_DEC_REFCOUNT(socket);
    return result;
  }
  kspin_unlock(&g_tcp.lock);

  // No connected socket found, look for listening sockets.
  DEFINT_PUSH_AND_DISABLE();  // For consistency and to mark for SMP-conversion.
  sockmap_t* sm = net_get_sockmap(AF_INET, IPPROTO_TCP);
  socket_t* socket_base = sockmap_find(sm, (const struct sockaddr*)&mdata.dst);
  if (socket_base) {
    KASSERT_DBG(socket_base->s_type == SOCK_STREAM);
    KASSERT_DBG(socket_base->s_protocol == IPPROTO_TCP);
    socket_tcp_t* socket = (socket_tcp_t*)socket_base;
    refcount_inc(&socket->ref);
    DEFINT_POP();
    bool result = tcp_dispatch_to_sock(socket, pb);
    TCP_DEC_REFCOUNT(socket);
    return result;
  }
  DEFINT_POP();

  // Incoming packet didn't match any listeners.  Restore the original IP header
  // and return to the IP stack (in case any raw sockets want it).
  // TODO(tcp): send a RST?
  // Restore the original IP header.
  pbuf_push_header(pb, mdata.ip_hdr_len);

  return false;
}

// Per-socket-state handlers for incoming packets.
static bool tcp_handle_synsent(socket_tcp_t* socket, pbuf_t* pb);
static bool tcp_handle_established(socket_tcp_t* socket, pbuf_t* pb);
static bool tcp_handle_lastack(socket_tcp_t* socket, pbuf_t* pb);

static void finish_protocol_close(socket_tcp_t* socket);

static bool tcp_dispatch_to_sock(socket_tcp_t* socket, pbuf_t* pb) {
  // Racily read the current state.  If the state changes between now and
  // actually handling the packet below, that's fine --- it's equivalent to the
  // packet being dropped or reordered.
  kspin_lock(&socket->spin_mu);
  socktcp_state_t racy_state = socket->state;
  kspin_unlock(&socket->spin_mu);

  bool result = false;
  switch (racy_state) {
    case TCP_SYN_SENT:
      result = tcp_handle_synsent(socket, pb);
      break;

    case TCP_ESTABLISHED:
      result = tcp_handle_established(socket, pb);
      break;

    case TCP_LAST_ACK:
      result = tcp_handle_lastack(socket, pb);
      break;

    case TCP_CLOSE_WAIT:
    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
      // TODO(tcp): handle all of these
      die("unimplemented");
  }
  if (result) {
    pbuf_free(pb);
  }
  return result;
}

static bool tcp_handle_synsent(socket_tcp_t* socket, pbuf_t* pb) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  if (tcp_hdr->flags & TCP_FLAG_RST) {
    KLOG(DEBUG, "TCP: socket %p received RST\n", socket);
    kspin_lock(&socket->spin_mu);
    socket->error = ECONNREFUSED;
    finish_protocol_close(socket);
    kspin_unlock(&socket->spin_mu);
    return true;
  }

  bool is_synack =
      (tcp_hdr->flags & TCP_FLAG_SYN) && (tcp_hdr->flags & TCP_FLAG_ACK);
  if (!is_synack) {
    // TODO(tcp): handle simultaneous open case (just SYN)
    // TODO(tcp): handle unexpected packets (sent RST)
    die("unexpected packet in SYN_SENT");
  }

  if (tcp_hdr->flags & ~(TCP_FLAG_SYN | TCP_FLAG_ACK) ||
      btoh32(tcp_hdr->ack) != socket->seq) {
    // TODO(tcp): handle unexpected packets (sent RST)
    die("unexpected packet in SYN_SENT");
  }

  kspin_lock(&socket->spin_mu);
  // This should be _very_ unusual.
  if (socket->state != TCP_SYN_SENT) {
    KLOG(INFO,
         "TCP: socket transitioned out of SYN_SENT before SYN-ACK could be "
         "processed\n");
    kspin_unlock(&socket->spin_mu);
    return false;
  }

  set_state(socket, TCP_ESTABLISHED, "SYN-ACK received");
  socket->remote_seq = btoh32(tcp_hdr->seq);
  socket->remote_ack = btoh32(tcp_hdr->ack);
  socket->remote_wndsize = btoh16(tcp_hdr->wndsize);
  kspin_unlock(&socket->spin_mu);

  int result = tcp_send_ack(socket);
  // TODO(tcp): handle errors gracefully.
  KASSERT(result == 0);

  return true;
}

static bool tcp_handle_established(socket_tcp_t* socket, pbuf_t* pb) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  bool is_fin = (tcp_hdr->flags & TCP_FLAG_FIN);
  if (!is_fin) {
    // TODO(tcp): handle everything else
    die("unexpected packet in ESTABLISHED");
  }

  if (tcp_hdr->flags & ~(TCP_FLAG_FIN | TCP_FLAG_ACK)) {
    // TODO(tcp): handle unexpected packets (sent RST)
    die("unexpected packet in ESTABLISHED");
  }

  // Check sequence number.
  kspin_lock(&socket->spin_mu);
  if (btoh32(tcp_hdr->seq) != socket->remote_seq + 1) {
    // TODO(tcp): handle out-of-order packets properly.
    die("unexpected out-of-order packet in ESTABLISHED");
  }

  // This should be _very_ unusual.
  if (socket->state != TCP_ESTABLISHED) {
    KLOG(INFO,
         "TCP: socket transitioned out of ESTABLISHED before packet could be "
         "processed\n");
    kspin_unlock(&socket->spin_mu);
    return false;
  }

  KASSERT(is_fin);
  set_state(socket, TCP_CLOSE_WAIT, "FIN received");
  socket->remote_seq = btoh32(tcp_hdr->seq);
  if (tcp_hdr->flags & TCP_FLAG_ACK) socket->remote_ack = btoh32(tcp_hdr->ack);
  socket->remote_wndsize = btoh16(tcp_hdr->wndsize);
  kspin_unlock(&socket->spin_mu);

  int result = tcp_send_ack(socket);
  // TODO(tcp): handle errors gracefully.
  KASSERT(result == 0);

  return true;
}

static bool tcp_handle_lastack(socket_tcp_t* socket, pbuf_t* pb) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  if (tcp_hdr->flags != TCP_FLAG_ACK) {
    // TODO(tcp): handle everything else
    die("unexpected packet in LAST_ACK");
  }

  kspin_lock(&socket->spin_mu);
  // Check sequence number.
  if (btoh32(tcp_hdr->ack) != socket->seq) {
    // TODO(tcp): handle out-of-order packets properly.
    die("unexpected out-of-order packet in LAST_ACK");
  }

  // This should be _very_ unusual.
  if (socket->state != TCP_LAST_ACK) {
    KLOG(INFO,
         "TCP: socket transitioned out of LAST_ACK before packet could be "
         "processed\n");
    kspin_unlock(&socket->spin_mu);
    return false;
  }

  finish_protocol_close(socket);
  kspin_unlock(&socket->spin_mu);

  return true;
}

// Closes the socket on the protocol side when all protocol ops are complete.
// Could be called from a user context or a defint.
static void finish_protocol_close(socket_tcp_t* socket) {
  KASSERT(kspin_is_held(&socket->spin_mu));
  // TODO(tcp): assert that we're coming from a last-to-terminal state, OR that
  // an error has occurred.

  KASSERT(socket->state != TCP_CLOSED_DONE);

  // If connected, remove from the connection table.
  if (socket->connected_addr.sa_family != AF_UNSPEC) {
    KASSERT(socket->state != TCP_CLOSED);
    KASSERT(socket->bind_addr.sa_family != AF_UNSPEC);
    tcp_key_t tcpkey = tcp_key((const struct sockaddr*)&socket->bind_addr,
                               (const struct sockaddr*)&socket->connected_addr);
    kspin_lock(&g_tcp.lock);
    void* val;
    if (htbl_get(&g_tcp.connected_sockets, tcpkey, &val) == 0) {
      KASSERT(val == socket);
      KASSERT(htbl_remove(&g_tcp.connected_sockets, tcpkey) == 0);
      KASSERT(refcount_dec(&socket->ref) > 0);
    } else {
      char buf1[SOCKADDR_PRETTY_LEN], buf2[SOCKADDR_PRETTY_LEN];
      KLOG(DFATAL,
           "TCP: socket %p connected (bound to %s, connected to %s) but not in "
           "connected sockets table\n",
           socket,
           sockaddr2str((struct sockaddr*)&socket->bind_addr,
                        sizeof(struct sockaddr_storage), buf1),
           sockaddr2str((struct sockaddr*)&socket->connected_addr,
                        sizeof(struct sockaddr_storage), buf2));
    }
    kspin_unlock(&g_tcp.lock);
    clear_addr(&socket->bind_addr);
    clear_addr(&socket->connected_addr);
  } else if (socket->bind_addr.sa_family != AF_UNSPEC) {
    // If unconnected but bound, remove from the bound sockets map.
    // TODO(tcp): expand this when more states are implemented (and tested).
    KASSERT(socket->state == TCP_CLOSED || socket->state == TCP_SYN_SENT);
    KASSERT_DBG(socket->bind_addr.sa_family ==
                (sa_family_t)socket->base.s_domain);
    DEFINT_PUSH_AND_DISABLE();
    sockmap_t* sm = net_get_sockmap(socket->bind_addr.sa_family, IPPROTO_TCP);
    socket_t* removed =
        sockmap_remove(sm, (struct sockaddr*)&socket->bind_addr);
    KASSERT(removed == &socket->base);
    KASSERT(refcount_dec(&socket->ref) > 0);
    DEFINT_POP();
    clear_addr(&socket->bind_addr);
  }

  KASSERT_DBG(socket->bind_addr.sa_family == AF_UNSPEC);
  KASSERT_DBG(socket->connected_addr.sa_family == AF_UNSPEC);
  set_state(socket, TCP_CLOSED_DONE, "protocol finished");
}

// Socket cleanup has three stages:
//  1a) last FD closed (sock_tcp_fd_cleanup called) --- clean up any
//      FD/VFS-related components, transfer ownership of the socket to the TCP
//      module, kick off protocol shutdown if necessary.  Always triggered from
//      a user context.
//  1b) socket (protocol) closed --- the TCP connection is complete.  Remove the
//      socket from appropriate data structures and set its state to
//      CLOSED_DONE.  May be triggered from a user or defint context.
//  2) free --- when both (1a) and (1b) are done, free all memory.
//
//  (1a) and (1b) can happen in any order.  If (1a) happens first, it will kick
//  off closing to get to (1b).
//
//  We decouple (2) and base it on a refcount so that we don't have to hold a
//  global lock during all of defint handling --- we can grab a matching socket,
//  increment its refcount, then unlock the connection table without having to
//  worry about another thread freeing the socket out from under us (assuming
//  SMP).
static void sock_tcp_fd_cleanup(socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;

  kmutex_lock(&socket->mu);
  // TODO(aoates): is this the proper way to handle this, or should vfs_poll()
  // retain a reference to the file containing this socket (and other pollables)
  // to ensure the file isn't destroyed while someone is polling it?
  poll_trigger_event(&socket->poll_event, KPOLLNVAL);
  KASSERT(list_empty(&socket->poll_event.refs));

  // The file descriptor is gone, there should be no other threads able to
  // reference or block on the socket.
  KASSERT(kthread_queue_empty(&socket->q));

  kspin_lock(&socket->spin_mu);
  if (socket->state == TCP_CLOSED) {
    finish_protocol_close(socket);
  }

  if (socket->state != TCP_CLOSED_DONE) {
    // TODO(tcp): close socket and defer cleanup after timeout.
    die("Cannot cleanup non-closed socket");
  }
  kspin_unlock(&socket->spin_mu);
  TCP_DEC_REFCOUNT(socket);
}

static int sock_tcp_shutdown(socket_t* socket_base, int how) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  if (how != SHUT_WR) {
    // TODO(tcp): implement
    KLOG(FATAL, "shutdown unimplemented");
    return -ENOTSUP;
  }

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;
  kmutex_lock(&sock->mu);

  kspin_lock(&sock->spin_mu);
  if (sock->state != TCP_CLOSE_WAIT) {
    // TODO(tcp): handle this in other states that can close, and error
    // correctly in states that can't close.
    kspin_unlock(&sock->spin_mu);
    kmutex_unlock(&sock->mu);
    die("unimplemented");
    return -ENOTCONN;
  }

  set_state(sock, TCP_LAST_ACK, "shutdown() sending FIN");
  kspin_unlock(&sock->spin_mu);

  // Send the final FIN.
  int result = tcp_send_fin(sock);
  kmutex_unlock(&sock->mu);

  // TODO(tcp): set up retry timer to retry sending the FIN
  // TODO(tcp): if we fail to send the FIN, should we go back to CLOSE_WAIT?
  // Try to retransmit later?  Just error the socket?
  return result;
}

// TODO(aoates): this is almost exactly the same as UDP's bind; refactor/share?
static int sock_tcp_bind_locked(socket_tcp_t* socket,
                                const struct sockaddr* address,
                                socklen_t address_len, bool allow_rebind) {
  kmutex_assert_is_held(&socket->mu);
  if (!is_in_state(socket, TCP_CLOSED)) {
    return -EINVAL;
  }

  if (socket->bind_addr.sa_family != AF_UNSPEC &&
      (!inet_is_anyaddr((const struct sockaddr*)&socket->bind_addr) ||
       !allow_rebind)) {
    return -EINVAL;
  }

  // TODO(tcp): check for _connected_ sockets and fail if there are any bound to
  // the same address unless SO_REUSEADDR is set.

  netaddr_t naddr;
  int naddr_port;
  int result = sock2netaddr(address, address_len, &naddr, &naddr_port);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EADDRNOTAVAIL;

  result = inet_bindable(&naddr);
  if (result) return result;

  DEFINT_PUSH_AND_DISABLE();
  sockmap_t* sm = net_get_sockmap(AF_INET, IPPROTO_TCP);

  // As a special case, we may allow rebinding to a "more specific" IP on an
  // implicit bind during connection.
  if (allow_rebind && socket->bind_addr.sa_family != AF_UNSPEC) {
    // Sanity check --- we should be rebinding from <any-addr>:$PORT to
    // <specific-addr>:$PORT.  We should not have previously been able to bind
    // to the any-port (i.e. either bind_addr should be AF_UNSPEC, or have a
    // specific port, possibly chosen automatically).
    KASSERT_DBG(get_sockaddrs_port(&socket->bind_addr) == naddr_port);
    KASSERT_DBG(naddr_port != 0);
    KASSERT(sockmap_remove(sm, (const struct sockaddr*)&socket->bind_addr) ==
            (socket_t*)socket);
    KASSERT(refcount_dec(&socket->ref) > 0);
  }

  // If necessary, pick a free port.
  if (naddr_port == 0) {
    in_port_t free_port = sockmap_free_port(sm, address);
    if (free_port == 0) {
      klogfm(KL_NET, WARNING, "net: out of ephemeral ports\n");
      DEFINT_POP();
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
      sockmap_insert(sm, (struct sockaddr*)&addr_with_port, &socket->base);
  DEFINT_POP();
  if (!inserted) {
    return -EADDRINUSE;
  }

  refcount_inc(&socket->ref);
  kmemset(&socket->bind_addr, 0, sizeof(struct sockaddr_storage));
  kmemcpy(&socket->bind_addr, &addr_with_port, address_len);

  char buf[SOCKADDR_PRETTY_LEN];
  KLOG(DEBUG2, "TCP: socket %p bound to %s\n", socket,
       sockaddr2str((const struct sockaddr*)&socket->bind_addr,
                    sizeof(socket->bind_addr), buf));
  return 0;
}

static int sock_tcp_bind(socket_t* socket_base, const struct sockaddr* address,
                         socklen_t address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);
  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  KMUTEX_AUTO_LOCK(lock, &socket->mu);
  return sock_tcp_bind_locked(socket, address, address_len,
                              /* allow_rebind = */ false);
}

static int sock_tcp_listen(socket_t* socket_base, int backlog) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_accept(socket_t* socket_base, int fflags,
                            struct sockaddr* address, socklen_t* address_len,
                            socket_t** socket_out) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_connect(socket_t* socket_base, int fflags,
                            const struct sockaddr* address,
                            socklen_t address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);
  if (!address) return -EDESTADDRREQ;

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;
  kmutex_lock(&sock->mu);

  kspin_lock(&sock->spin_mu);
  if (sock->state != TCP_CLOSED) {
    int result = 0;
    // TODO(tcp): return -EOPNOTSUPP for listening sockets.
    switch (get_state_type(sock->state)) {
      case TCPSTATE_PRE_ESTABLISHED:
        result = -EALREADY;
        break;
      case TCPSTATE_ESTABLISHED:
        result = -EISCONN;
        break;
      case TCPSTATE_POST_ESTABLISHED:
        result = -EINVAL;
        break;
    }
    kspin_unlock(&sock->spin_mu);
    kmutex_unlock(&sock->mu);
    return result;
  }
  kspin_unlock(&sock->spin_mu);

  netaddr_t dest;
  int result = sock2netaddr(address, address_len, &dest, NULL);
  if (result && result != -EAFNOSUPPORT) result = -EDESTADDRREQ;
  if (result == 0 && dest.family != AF_UNSPEC &&
      dest.family != (addrfam_t)sock->base.s_domain) {
    result = -EAFNOSUPPORT;
  }
  if (result) {
    kmutex_unlock(&sock->mu);
    return result;
  }

  result = bind_if_necessary(sock, address, address_len);
  if (result) {
    kmutex_unlock(&sock->mu);
    return result;
  }

  // Hacky sanity check, should be checked above
  KASSERT_DBG(address_len >= (socklen_t)sizeof(struct sockaddr_in));
  tcp_key_t tcpkey = tcp_key((const struct sockaddr*)&sock->bind_addr, address);

  // Update our state and put us in the connected sockets table.  State must be
  // updated before the table, or atomically together.
  kspin_lock(&sock->spin_mu);
  // Mutex locked, and TCP_CLOSED is a defint-stable STATE.
  KASSERT_DBG(sock->state == TCP_CLOSED);

  kspin_lock(&g_tcp.lock);
  void* val;
  if (htbl_get(&g_tcp.connected_sockets, tcpkey, &val) == 0) {
    KLOG(DEBUG, "TCP: unable to connect socket, 5-tuple in use\n");
    kspin_unlock(&g_tcp.lock);
    kspin_unlock(&sock->spin_mu);
    kmutex_unlock(&sock->mu);
    return -EADDRINUSE;
  }

  set_state(sock, TCP_SYN_SENT, "sending connect SYN");
  kmemcpy(&sock->connected_addr, address, address_len);
  htbl_put(&g_tcp.connected_sockets, tcpkey, sock);
  refcount_inc(&sock->ref);
  kspin_unlock(&g_tcp.lock);

  // Now remove us from the "bound" map --- we have succesfully transitioned to
  // the connected map, and other sockets can now bind to our IP/port if
  // SO_REUSE* is set (when implemented).  In the case of an implicit bind,
  // we're removing the entry we just added, whatever.
  // N.B.: put in separate block due to interaction between DEFINT_PUSH safety
  // checks and the spinlock (so DEFINT_POP() is validated at the end of the
  // block, rather than the end of the function --- when defints may be enabled
  // again).  Leaving DEFINT_* in as a placeholder for future upgrade to a
  // spinlock even though they are no-ops here.
  {
    DEFINT_PUSH_AND_DISABLE();
    sockmap_t* sm = net_get_sockmap(AF_INET, IPPROTO_TCP);
    KASSERT(sockmap_remove(sm, (const struct sockaddr*)&sock->bind_addr) ==
            (socket_t*)sock);
    DEFINT_POP();
  }
  kspin_unlock(&sock->spin_mu);
  KASSERT(refcount_dec(&sock->ref) > 0);

  // Send the initial SYN.
  result = tcp_send_syn(sock, fflags);
  kmutex_unlock(&sock->mu);
  if (result) {
    return result;
  }

  // TODO(tcp): set up retry timer to retry sending the SYN.
  // TODO(tcp): implement non-blocking connect (and return EINPROGRESS).

  // Wait until the socket is established or closes (with an error, presumably).
  kspin_lock(&sock->spin_mu);
  apos_ms_t now = get_time_ms();
  apos_ms_t timeout_end = now + SOCKET_CONNECT_TIMEOUT_MS;
  // TODO(tcp): handle other transitions as well (in particular, transition to
  // CLOSE_WAIT before this thread wakes up).
  while (now < timeout_end && sock->state != TCP_ESTABLISHED &&
         sock->state != TCP_CLOSED_DONE) {
    int wait_result =
        scheduler_wait_on_splocked(&sock->q, timeout_end - now, &sock->spin_mu);
    if (wait_result == SWAIT_TIMEOUT) {
      result = -ETIMEDOUT;
      break;
    } else if (wait_result == SWAIT_INTERRUPTED) {
      result = -EINTR;
      break;
    } else {
      KASSERT(wait_result == SWAIT_DONE);
    }
  }

  if (sock->error) {
    KASSERT(sock->state == TCP_CLOSED_DONE);
    result = -sock->error;
    sock->error = 0;
  }

  if (result == 0) {
    KASSERT_DBG(sock->state == TCP_ESTABLISHED);
  }
  kspin_unlock(&sock->spin_mu);

  return result;
}

static int sock_tcp_accept_queue_length(const socket_t* socket_base) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

ssize_t sock_tcp_recvfrom(socket_t* socket_base, int fflags, void* buffer,
                          size_t length, int sflags, struct sockaddr* address,
                          socklen_t* address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

ssize_t sock_tcp_sendto(socket_t* socket_base, int fflags, const void* buffer,
                        size_t length, int sflags,
                        const struct sockaddr* dest_addr, socklen_t dest_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_getsockname(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  KMUTEX_AUTO_LOCK(lock, &socket->mu);
  kspin_lock(&socket->spin_mu);
  int result = 0;
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    kmemcpy(address, &socket->bind_addr, sizeof(socket->bind_addr));
  } else if (socket->state == TCP_CLOSED) {
    // We haven't bound yet.
    inet_make_anyaddr(socket_base->s_domain, address);
  } else {
    // In every pre-established state, we should either be CLOSED, or have
    // bound (and therefore be caught above either way).
    KASSERT_DBG(get_state_type(socket->state) != TCPSTATE_PRE_ESTABLISHED);
    result = -EINVAL;
  }
  kspin_unlock(&socket->spin_mu);
  return result;
}

static int sock_tcp_getpeername(socket_t* socket_base,
                                struct sockaddr* address) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  KMUTEX_AUTO_LOCK(lock, &socket->mu);
  kspin_lock(&socket->spin_mu);
  int result = 0;
  if (get_state_type(socket->state) == TCPSTATE_PRE_ESTABLISHED) {
    result = -ENOTCONN;
  } else if (get_state_type(socket->state) == TCPSTATE_POST_ESTABLISHED) {
    result = -EINVAL;
  } else if (socket->connected_addr.sa_family != AF_UNSPEC) {
    KASSERT_DBG(socket->bind_addr.sa_family ==      // If connected, must be
                socket->connected_addr.sa_family);  // bound as well.
    kmemcpy(address, &socket->connected_addr, sizeof(socket->connected_addr));
  } else {
    KLOG(DFATAL, "TCP: socket %p connected_addr should be set but isn't\n",
         socket_base);
    result = -ENOTCONN;
  }
  kspin_unlock(&socket->spin_mu);
  return result;
}

static int sock_tcp_poll(socket_t* socket_base, short event_mask,
                         poll_state_t* poll) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  // TODO(tcp): implement
  return -ENOTSUP;
}

static int sock_tcp_getsockopt(socket_t* socket_base, int level, int option,
                                void* restrict val,
                                socklen_t* restrict val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_STREAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  KMUTEX_AUTO_LOCK(lock, &socket->mu);

  if (level == IPPROTO_TCP && option == SO_TCP_SEQ_NUM) {
    kspin_lock(&socket->spin_mu);
    if (socket->state != TCP_CLOSED) {
      kspin_unlock(&socket->spin_mu);
      return -EISCONN;
    }

    int seq = (int)socket->seq;
    kspin_unlock(&socket->spin_mu);
    return getsockopt_int(val, val_len, seq);
  }

  return -ENOPROTOOPT;
}

static int sock_tcp_setsockopt(socket_t* socket_base, int level, int option,
                               const void* val, socklen_t val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_STREAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  KMUTEX_AUTO_LOCK(lock, &socket->mu);

  if (level == IPPROTO_TCP && option == SO_TCP_SEQ_NUM) {
    int seq;
    int result = setsockopt_int(val, val_len, &seq);
    if (result) {
      return result;
    }

    kspin_lock(&socket->spin_mu);
    if (socket->state != TCP_CLOSED) {
      kspin_unlock(&socket->spin_mu);
      return -EISCONN;
    }
    socket->seq = (uint32_t)seq;
    kspin_unlock(&socket->spin_mu);
    return 0;
  }

  return -ENOPROTOOPT;
}

static const socket_ops_t g_tcp_socket_ops = {
  &sock_tcp_fd_cleanup,
  &sock_tcp_shutdown,
  &sock_tcp_bind,
  &sock_tcp_listen,
  &sock_tcp_accept,
  &sock_tcp_connect,
  &sock_tcp_accept_queue_length,
  &sock_tcp_recvfrom,
  &sock_tcp_sendto,
  &sock_tcp_getsockname,
  &sock_tcp_getpeername,
  &sock_tcp_poll,
  &sock_tcp_getsockopt,
  &sock_tcp_setsockopt,
};
