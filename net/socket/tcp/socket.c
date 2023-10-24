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
#include "common/errno.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/math.h"
#include "common/refcount.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/eth/ethertype.h"
#include "net/inet.h"
#include "net/ip/checksum.h"
#include "net/ip/ip.h"
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
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/tcp.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

#define DEFAULT_LISTEN_BACKLOG 10

#define SOCKET_DEFAULT_BUFSIZE (16 * 1024)

#define MAX_BUF_SIZE (1 * 1024 * 1024)

#define SOCKET_CONNECT_TIMEOUT_MS 60000

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

  void* recvbuf = kmalloc(SOCKET_DEFAULT_BUFSIZE);
  if (!recvbuf) {
    kfree(sock);
    return -ENOMEM;
  }

  void* sendbuf = kmalloc(SOCKET_DEFAULT_BUFSIZE);
  if (!sendbuf) {
    kfree(recvbuf);
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
  circbuf_init(&sock->send_buf, sendbuf, SOCKET_DEFAULT_BUFSIZE);
  circbuf_init(&sock->recv_buf, recvbuf, SOCKET_DEFAULT_BUFSIZE);
  sock->send_shutdown = false;
  sock->connect_timeout_ms = SOCKET_CONNECT_TIMEOUT_MS;
  sock->recv_timeout_ms = -1;
  sock->send_timeout_ms = -1;
  sock->send_next = gen_seq_num(sock);
  sock->send_unack = sock->send_next;
  sock->recv_wndsize = circbuf_available(&sock->recv_buf);
  sock->cwnd = 1000;  // TODO(tcp): implement congestion control.
  sock->mss = 536;  // TODO(tcp): determine MSS dynamically.
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
  kfree(socket->send_buf.buf);
  kfree(socket->recv_buf.buf);
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

// Sends data and/or a FIN if available.  If no data is ready to be sent,
// returns -EAGAIN (and doesn't send any packets).
static int tcp_send_datafin(socket_tcp_t* socket, bool allow_block) {
  // Figure out how much data to send.
  kspin_lock(&socket->spin_mu);
  if (get_state_type(socket->state) != TCPSTATE_ESTABLISHED) {
    kspin_unlock(&socket->spin_mu);
    return -EAGAIN;
  }

  uint32_t unacked_bytes = socket->send_next - socket->send_unack;
  KASSERT_DBG(socket->send_buf.len >= unacked_bytes);
  size_t data_to_send =
      min(socket->cwnd,
          socket->send_wndsize - min(socket->send_wndsize, unacked_bytes));
  data_to_send = min(data_to_send, socket->send_buf.len - unacked_bytes);
  data_to_send = min(data_to_send, socket->mss);

  ip4_pseudo_hdr_t pseudo_ip;
  pbuf_t* pb = NULL;
  int result = tcp_create_datafin(socket, socket->send_next, data_to_send,
                                  &pseudo_ip, &pb);
  if (result) {
    if (result != -EAGAIN) {
      KLOG(DFATAL, "TCP: unable to create data/FIN packet: %s\n",
           errorname(-result));
    }
    kspin_unlock(&socket->spin_mu);
    return result;
  }
  socket->send_next += data_to_send;
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  bool sent_fin = (tcp_hdr->flags & TCP_FLAG_FIN);
  if (sent_fin) {
    socket->send_next++;
    switch (socket->state) {
      case TCP_CLOSE_WAIT:
        set_state(socket, TCP_LAST_ACK, "sending FIN");
        break;

      case TCP_CLOSED_DONE:
      case TCP_LAST_ACK:
      case TCP_ESTABLISHED:
      case TCP_CLOSED:
      case TCP_SYN_SENT:
        KLOG(DFATAL, "TCP: socket %p sent FIN in invalid state %s\n", socket,
             state2str(socket->state));
        break;
    }
  }
  kspin_unlock(&socket->spin_mu);

  tcp_hdr->checksum =
      ip_checksum2(&pseudo_ip, sizeof(pseudo_ip), pbuf_get(pb), pbuf_size(pb));

  KLOG(DEBUG2, "TCP: socket %p transmitting %s%zu bytes of data\n", socket,
       sent_fin ? "FIN and " : "", data_to_send);
  ip4_add_hdr(pb, pseudo_ip.src_addr, pseudo_ip.dst_addr, IPPROTO_TCP);
  return ip_send(pb, allow_block);
}

static bool tcp_dispatch_to_sock(socket_tcp_t* socket, const pbuf_t* pb,
                                 const tcp_packet_metadata_t* md);

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
    bool result = tcp_dispatch_to_sock(socket, pb, &mdata);
    if (result) {
      pbuf_free(pb);
    }
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
    bool result = tcp_dispatch_to_sock(socket, pb, &mdata);
    if (result) {
      pbuf_free(pb);
    }
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

// Actions to take based on a packet.
typedef enum {
  TCP_PACKET_DONE,      // We're done with the packet.
  TCP_DROP_BAD_PKT,     // Drop the packet, it is bad.
  TCP_SEND_ACK,         // Send an ACK.
} tcp_pkt_action_t;

// Handlers for different types of packet scenarios.  Multiple of these may be
// called for a particular incoming packet depending on its contents.

// Specific handler for SYN_SENT state.
static tcp_pkt_action_t tcp_handle_in_synsent(socket_tcp_t* socket,
                                              const pbuf_t* pb);

static tcp_pkt_action_t tcp_handle_syn(socket_tcp_t* socket, const pbuf_t* pb);
static void tcp_handle_ack(socket_tcp_t* socket, const pbuf_t* pb);
static tcp_pkt_action_t tcp_handle_fin(socket_tcp_t* socket, const pbuf_t* pb);
static tcp_pkt_action_t tcp_handle_rst(socket_tcp_t* socket, const pbuf_t* pb);
static tcp_pkt_action_t tcp_handle_data(socket_tcp_t* socket, const pbuf_t* pb,
                                        const tcp_packet_metadata_t* md);

static void finish_protocol_close(socket_tcp_t* socket);

// Returns true if the given segment is valid (overlaps our window).
static bool validate_seq(const socket_tcp_t* socket, uint32_t seq,
                         uint32_t seg_len) {
  if (seg_len == 0) {
    if (socket->recv_wndsize == 0) {
      return seq == socket->recv_next;
    } else {
      return seq_le(socket->recv_next, seq) &&
          seq_lt(seq, socket->recv_next + socket->recv_wndsize);
    }
  } else {
    if (socket->recv_wndsize == 0) {
      return false;
    } else {
      uint32_t seg_end = seq + seg_len - 1;
      return (seq_le(socket->recv_next, seq) &&
              seq_lt(seq, socket->recv_next + socket->recv_wndsize)) ||
          (seq_le(socket->recv_next, seg_end) &&
           seq_lt(seg_end, socket->recv_next + socket->recv_wndsize));
    }
  }
}

static bool tcp_dispatch_to_sock(socket_tcp_t* socket, const pbuf_t* pb,
                                 const tcp_packet_metadata_t* md) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  tcp_pkt_action_t action = TCP_PACKET_DONE;
  bool send_ack = false;

  // Handle SYN-SENT as a special case first.
  kspin_lock(&socket->spin_mu);
  if (socket->state == TCP_SYN_SENT) {
    action = tcp_handle_in_synsent(socket, pb);
    goto done;
  }

  // Check the sequence number of the packet.  The packet must overlap with the
  // receive window.
  uint32_t seq = btoh32(tcp_hdr->seq);
  if (!validate_seq(socket, seq, md->data_len)) {
    // TODO(tcp): check RST and if not set, send an ACK.
    KLOG(DEBUG2, "TCP: socket %p got out-of-window packet, dropping\n", socket);
    action = TCP_DROP_BAD_PKT;
    goto done;
  }

  // TODO(tcp): trim the packer rather than requiring strict window alignment.
  if (seq != socket->recv_next) {
    KLOG(DEBUG2,
         "TCP: socket %p dropping packet not aligned with start of window\n",
         socket);
    action = TCP_SEND_ACK;
    goto done;
  }

  if (tcp_hdr->flags & TCP_FLAG_RST) {
    action = tcp_handle_rst(socket, pb);
    // We should always be done after a RST.
    goto done;
  }

  // Next handle SYN and SYN-ACK.
  if (tcp_hdr->flags & TCP_FLAG_SYN) {
    action = tcp_handle_syn(socket, pb);
    goto done;
  }

  if (!(tcp_hdr->flags & TCP_FLAG_ACK)) {
    KLOG(INFO, "TCP: socket %p dropping packet without ACK\n", socket);
    action = TCP_DROP_BAD_PKT;
    goto done;
  }

  tcp_handle_ack(socket, pb);

  if (tcp_hdr->flags & TCP_FLAG_URG) {
    // TODO(tcp): handle gracefully
    KLOG(DFATAL, "TCP: socket %p cannot handle URG data\n", socket);
    action = TCP_DROP_BAD_PKT;
    goto done;
  }

  if (md->data_len > 0) {
    if (tcp_handle_data(socket, pb, md) == TCP_SEND_ACK)
      send_ack = true;
  }

  if (tcp_hdr->flags & TCP_FLAG_FIN) {
    action = tcp_handle_fin(socket, pb);
  }

done:
  kspin_unlock(&socket->spin_mu);

  int result = 0;
  switch (action) {
    case TCP_DROP_BAD_PKT:
      KLOG(DEBUG2, "TCP: socket %p dropping bad packet\n", socket);
      // Fall through.

    case TCP_PACKET_DONE:
      break;

    case TCP_SEND_ACK:
      send_ack = true;
  }

  result = tcp_send_datafin(socket, false);
  if (result == 0) {
    send_ack = false;  // We sent data, that includes an ack
  } else if (result != -EAGAIN) {
    KLOG(WARNING, "TCP: socket %p unable to send data: %s\n", socket,
         errorname(-result));
  }

  if (send_ack) {
    result = tcp_send_ack(socket);
    if (result != 0) {
      KLOG(WARNING, "TCP: socket %p unable to send ACK: %s\n", socket,
           errorname(-result));
    }
  }

  return true;
}

static tcp_pkt_action_t tcp_handle_syn(socket_tcp_t* socket, const pbuf_t* pb) {
  // TODO(tcp): handle SYN in other states (connection reset).
  die("Can't handle SYN");
}

static void tcp_handle_ack(socket_tcp_t* socket, const pbuf_t* pb) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(tcp_hdr->flags & TCP_FLAG_ACK);

  // TODO(tcp): handle out-of-order/duplicate ACKs properly.
  // TODO(tcp): handle invalid (future) ACKs correctly.
  uint32_t ack = btoh32(tcp_hdr->ack);
  if (seq_gt(ack, socket->send_next)) {
    KLOG(DFATAL, "TCP: future ACKs unimplemented\n");
    return;
  } else if (seq_lt(ack, socket->send_unack)) {
    return;
  }

  uint32_t bytes_acked = ack - socket->send_unack;
  if (bytes_acked > 0 && socket->state == TCP_LAST_ACK)  // Or FIN_WAIT, etc...
    bytes_acked--;  // Account for the FIN.

  ssize_t consumed = circbuf_consume(&socket->send_buf, bytes_acked);
  socket->send_buf_seq += consumed;
  if (consumed != (int)bytes_acked) {
    KLOG(DFATAL, "TCP: unable to consume all ACK'd bytes\n");
    return;
  }
  socket->send_unack = btoh32(tcp_hdr->ack);
  socket->send_wndsize = btoh16(tcp_hdr->wndsize);
  KLOG(DEBUG2,
       "TCP: socket %p had %u bytes acked (remaining unacked: %u; "
       "send_wndsize: %d)\n",
       socket, bytes_acked, socket->send_next - socket->send_unack,
       socket->send_wndsize);
  scheduler_wake_all(&socket->q);

  switch (socket->state) {
    case TCP_LAST_ACK:
      finish_protocol_close(socket);
      break;

    case TCP_SYN_SENT:
      // If a SYN flag was set, we should have transitioned out of SYN_SENT or
      // decided to drop the packet earlier.
      KASSERT(!(tcp_hdr->flags & TCP_FLAG_SYN));
      // TODO(tcp): send RST, this is not allowed.
      break;

    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
      // Nothing to do, rely on common ACK handling above.
      break;

    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
      KLOG(DFATAL, "TCP: socket %p packet received in CLOSED state\n", socket);
      break;
  }
}

static tcp_pkt_action_t tcp_handle_fin(socket_tcp_t* socket, const pbuf_t* pb) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  KLOG(DEBUG2, "TCP: socket %p received FIN\n", socket);

  switch (socket->state) {
    case TCP_ESTABLISHED:
      set_state(socket, TCP_CLOSE_WAIT, "FIN received");
      socket->recv_next++;
      return TCP_SEND_ACK;

    case TCP_LAST_ACK:
    case TCP_CLOSE_WAIT:
      // Nothing to do, stay in same state.
      return TCP_PACKET_DONE;

    case TCP_SYN_SENT:
    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
      KLOG(DFATAL, "TCP: socket %p FIN received in invalid state\n", socket);
      return TCP_DROP_BAD_PKT;
  }
  KLOG(FATAL, "TCP: socket %p in invalid state %d\n", socket, socket->state);
  return TCP_DROP_BAD_PKT;
}

static tcp_pkt_action_t tcp_handle_rst(socket_tcp_t* socket, const pbuf_t* pb) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  KLOG(DEBUG, "TCP: socket %p received RST\n", socket);

  if (btoh32(tcp_hdr->seq) != socket->recv_next) {
    KLOG(DEBUG, "TCP: socket %p out-of-order RST, dropping\n", socket);
    // TODO(tcp): send a challenge ack.
    return TCP_DROP_BAD_PKT;
  }

  // Reset the connection.
  switch (socket->state) {
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
      socket->error = ECONNRESET;
      // Drop any pending data.
      circbuf_clear(&socket->recv_buf);
      circbuf_clear(&socket->send_buf);
      socket->send_unack = socket->send_next;
      finish_protocol_close(socket);
      return TCP_PACKET_DONE;

    case TCP_LAST_ACK:
      // Don't clear the read buffer here --- let any pending data be consumed
      // (since we're not signalling an error).
      finish_protocol_close(socket);
      return TCP_PACKET_DONE;

    case TCP_SYN_SENT:
    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
      die("RST handling in invalid state");
  }
  KLOG(FATAL, "TCP: socket %p in invalid state %d\n", socket, socket->state);
  return TCP_DROP_BAD_PKT;
}

static tcp_pkt_action_t tcp_handle_data(socket_tcp_t* socket, const pbuf_t* pb,
                                        const tcp_packet_metadata_t* md) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);

  // TODO(tcp): handle packets that overlap the window (trim them).
  uint32_t seq = btoh32(tcp_hdr->seq);
  if (seq != socket->recv_next) {
    KLOG(DEBUG2,
         "TCP: socket %p ignoring out-of-order packet (seq=%d, recv_next=%d)\n",
         socket, seq, socket->recv_next);
    return TCP_SEND_ACK;
  }

  // TODO(tcp): handle FIN_WAIT states.
  if (socket->state != TCP_ESTABLISHED) {
    KLOG(DEBUG2,
         "TCP: socket %p ignoring %d bytes of data in non-connected state %s\n",
         socket, (int)md->data_len, state2str(socket->state));
    return TCP_DROP_BAD_PKT;
  }

  KASSERT_DBG(md->data_len <= pbuf_size(pb) - md->data_offset);
  ssize_t bytes_read = circbuf_write(
      &socket->recv_buf, pbuf_getc(pb) + md->data_offset, md->data_len);
  KASSERT(bytes_read >= 0);
  KLOG(DEBUG2, "TCP: socket %p received %d bytes of data\n", socket,
       (int)bytes_read);

  socket->recv_next += bytes_read;
  socket->recv_wndsize = circbuf_available(&socket->recv_buf);
  scheduler_wake_all(&socket->q);
  return TCP_SEND_ACK;
}

static tcp_pkt_action_t tcp_handle_in_synsent(socket_tcp_t* socket,
                                              const pbuf_t* pb) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));

  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    uint32_t seg_ack = btoh32(tcp_hdr->ack);
    // We don't transit data with our SYN, so this is the only acceptable ACK.
    if (seg_ack != socket->send_next) {
      // TODO(tcp): send a RST if RST flag isn't set.
      die("Out-of-order ACK received in SYN_SENT");
    }
  }

  if (tcp_hdr->flags & TCP_FLAG_RST) {
    KLOG(DEBUG, "TCP: socket %p received RST\n", socket);
    socket->error = ECONNREFUSED;
    finish_protocol_close(socket);
    return TCP_PACKET_DONE;
  }

  bool is_synack =
      (tcp_hdr->flags & TCP_FLAG_SYN) && (tcp_hdr->flags & TCP_FLAG_ACK);
  if (!is_synack) {
    // TODO(tcp): handle simultaneous open case (just SYN)
    // TODO(tcp): handle unexpected packets (sent RST)
    die("unexpected packet in SYN_SENT");
  }

  set_state(socket, TCP_ESTABLISHED, "SYN-ACK received");
  socket->recv_next = btoh32(tcp_hdr->seq) + 1;
  socket->send_unack = btoh32(tcp_hdr->ack);
  socket->send_wndsize = btoh16(tcp_hdr->wndsize);
  socket->send_buf_seq = socket->send_next;
  return TCP_SEND_ACK;
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
  kspin_lock(&sock->spin_mu);
  if (sock->send_shutdown || sock->state != TCP_CLOSE_WAIT) {
    // TODO(tcp): handle this in other states that can close, and error
    // correctly in states that can't close.
    kspin_unlock(&sock->spin_mu);
    return -ENOTCONN;
  }

  sock->send_shutdown = true;
  scheduler_wake_all(&sock->q);
  kspin_unlock(&sock->spin_mu);

  // Send the FIN if possible.
  int result = tcp_send_datafin(sock, true);
  if (result != 0 && result != -EAGAIN) {
    KLOG(WARNING, "TCP: socket %p unable to send data/FIN: %s\n",
         sock, errorname(-result));
  }
  return 0;  // Consider this a success even if sending FIN failed.
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
  apos_ms_t timeout_end = (sock->connect_timeout_ms < 0)
                              ? APOS_MS_MAX
                              : now + sock->connect_timeout_ms;
  while (now < timeout_end &&
         get_state_type(sock->state) == TCPSTATE_PRE_ESTABLISHED) {
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
    now = get_time_ms();
  }

  if (sock->error) {
    KASSERT(sock->state == TCP_CLOSED_DONE);
    result = -sock->error;
    sock->error = 0;
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

typedef enum {
  RECV_NOT_CONNECTED,   // We're not in a state where we can receive.
  RECV_BLOCK_FOR_DATA,  // recv() should block.
  RECV_ERROR,           // An error occurred.
  RECV_HAS_DATA,        // Data can be read.
  RECV_EOF,             // We are at EOF.
} recv_state_t;

static recv_state_t recv_state(const socket_tcp_t* socket) {
  if (socket->error != 0) {
    return RECV_ERROR;
  } else if (socket->recv_buf.len > 0) {
    return RECV_HAS_DATA;
  }

  switch (socket->state) {
    case TCP_CLOSE_WAIT:
    case TCP_CLOSED_DONE:
    case TCP_LAST_ACK:
      // No error, no data, and we've received a FIN --- return EOF.  Note that
      // we will return EOF after an error once the first call to recv() returns
      // the error --- this matches macos behavior, so seems fine.
      // TODO(tcp): include CLOSING and TIME_WAIT here.
      return RECV_EOF;

    case TCP_ESTABLISHED:
      // No data available but we could get some; block.
      // TODO(tcp): handle FIN_WAIT states as well.
      return RECV_BLOCK_FOR_DATA;

    case TCP_CLOSED:
    case TCP_SYN_SENT:
      return RECV_NOT_CONNECTED;
  }
  KLOG(DFATAL, "TCP: invalid socket state %d\n", (int)socket->state);
  return RECV_ERROR;
}

ssize_t sock_tcp_recvfrom(socket_t* socket_base, int fflags, void* buffer,
                          size_t length, int sflags, struct sockaddr* address,
                          socklen_t* address_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;

  // No need to lock the mutex --- no multi-stage operations here, just a simple
  // one that must coordinate with the defint code.
  kspin_lock(&sock->spin_mu);

  // Wait until data is available or the socket is closed.
  apos_ms_t now = get_time_ms();
  apos_ms_t timeout_end =
      (sock->recv_timeout_ms < 0) ? APOS_MS_MAX : now + sock->recv_timeout_ms;
  int result = 0;
  // TODO(tcp): tests for transitioning to FIN_WAIT* during this.
  while (now < timeout_end && recv_state(sock) == RECV_BLOCK_FOR_DATA) {
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
    now = get_time_ms();
  }

  if (result == 0) {
    switch (recv_state(sock)) {
      case RECV_NOT_CONNECTED:
        result = -ENOTCONN;
        break;

      case RECV_BLOCK_FOR_DATA:
        result = -ETIMEDOUT;
        break;

      case RECV_ERROR:
        KASSERT(sock->state == TCP_CLOSED_DONE);
        result = -sock->error;
        sock->error = 0;
        break;

      case RECV_EOF:
        // Skip read and return 0.
        break;

      case RECV_HAS_DATA:
        result = circbuf_read(&sock->recv_buf, buffer, length);
        KLOG(DEBUG2, "TCP: socket %p gave %d bytes to recvfrom()\n", sock,
             (int)result);
        sock->recv_wndsize = circbuf_available(&sock->recv_buf);
        break;
    }
  }
  kspin_unlock(&sock->spin_mu);

  return result;
}

typedef enum {
  SEND_NOT_CONNECTED,  // We're not in a state where we can send.
  SEND_BLOCK,          // send() should block.
  SEND_ERROR,          // An error occurred.
  SEND_HAS_BUFFER,     // Data can be buffered.
  SEND_IS_SHUTDOWN,    // We are at EOF.
} send_state_t;

static send_state_t send_state(const socket_tcp_t* socket) {
  if (socket->error != 0) {
    return SEND_ERROR;
  } else if (socket->send_shutdown) {
    return SEND_IS_SHUTDOWN;
  }

  switch (socket->state) {
    case TCP_CLOSED_DONE:
    case TCP_LAST_ACK:
      // TODO(tcp): include FIN_WAIT_*, CLOSING, and TIME_WAIT here.
      return SEND_IS_SHUTDOWN;

    case TCP_CLOSE_WAIT:
    case TCP_ESTABLISHED:
      // We can send data; block if no buffer space available.
      if (circbuf_available(&socket->send_buf) > 0) {
        return SEND_HAS_BUFFER;
      } else {
        return SEND_BLOCK;
      }

    case TCP_CLOSED:
    case TCP_SYN_SENT:
      return SEND_NOT_CONNECTED;
  }
  KLOG(DFATAL, "TCP: invalid socket state %d\n", (int)socket->state);
  return SEND_ERROR;
}

ssize_t sock_tcp_sendto(socket_t* socket_base, int fflags, const void* buffer,
                        size_t length, int sflags,
                        const struct sockaddr* dest_addr, socklen_t dest_len) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;

  // No need to lock the mutex --- no multi-stage operations here, just a simple
  // one that must coordinate with the defint code.
  kspin_lock(&sock->spin_mu);

  // Wait until buffer space is available or the socket is closed.
  apos_ms_t now = get_time_ms();
  apos_ms_t timeout_end =
      (sock->send_timeout_ms < 0) ? APOS_MS_MAX : now + sock->send_timeout_ms;
  int result = 0;
  // TODO(tcp): tests for transitioning to FIN_WAIT* during this.
  while (now < timeout_end && send_state(sock) == SEND_BLOCK) {
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
    now = get_time_ms();
  }

  if (result == 0) {
    switch (send_state(sock)) {
      case SEND_NOT_CONNECTED:
        result = -ENOTCONN;
        break;

      case SEND_BLOCK:
        result = -ETIMEDOUT;
        break;

      case SEND_ERROR:
        KASSERT(sock->state == TCP_CLOSED_DONE);
        result = -sock->error;
        sock->error = 0;
        break;

      case SEND_IS_SHUTDOWN:
        proc_force_signal(proc_current(), SIGPIPE);
        result = -EPIPE;
        break;

      case SEND_HAS_BUFFER:
        result = circbuf_write(&sock->send_buf, buffer, length);
        KLOG(DEBUG2, "TCP: socket %p buffered %d (of %d) bytes from sendto()\n",
             sock, (int)result, (int)length);
        break;
    }
  }
  kspin_unlock(&sock->spin_mu);

  if (result >= 0) {
    int bytes = result;
    result = tcp_send_datafin(sock, true);
    if (result == 0 || result == -EAGAIN) {
      result = bytes;
    }
  }

  return result;
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

static int getsockopt_bufsize(socket_tcp_t* socket, int option, void* val,
                              socklen_t* val_len) {
  KASSERT(option == SO_RCVBUF || option == SO_SNDBUF);
  circbuf_t* buf = option == SO_RCVBUF ? &socket->recv_buf : &socket->send_buf;

  kspin_lock(&socket->spin_mu);
  int buflen = (int)buf->buflen;
  kspin_unlock(&socket->spin_mu);
  return getsockopt_int(val, val_len, buflen);
}

static int setsockopt_bufsize(socket_tcp_t* socket, int option, const void* val,
                              socklen_t val_len) {
  KASSERT(option == SO_RCVBUF || option == SO_SNDBUF);
  circbuf_t* buf = option == SO_RCVBUF ? &socket->recv_buf : &socket->send_buf;

  int buflen;
  int result = setsockopt_int(val, val_len, &buflen);
  if (result) {
    return result;
  }

  if (buflen > MAX_BUF_SIZE) {
    return -EINVAL;
  }

  void* newbuf = kmalloc(buflen);
  if (!newbuf) {
    return -ENOMEM;
  }

  kspin_lock(&socket->spin_mu);
  if (socket->state != TCP_CLOSED) {
    kspin_unlock(&socket->spin_mu);
    kfree(newbuf);
    return -EISCONN;
  }
  KASSERT_DBG(buf->len == 0);
  KASSERT_DBG(buf->pos == 0);

  kfree(buf->buf);
  circbuf_init(buf, newbuf, buflen);
  socket->recv_wndsize = circbuf_available(&socket->recv_buf);
  kspin_unlock(&socket->spin_mu);
  return 0;
}

static int sock_tcp_getsockopt(socket_t* socket_base, int level, int option,
                                void* restrict val,
                                socklen_t* restrict val_len) {
  KASSERT_DBG(socket_base->s_type == SOCK_STREAM);
  KASSERT_DBG(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  KMUTEX_AUTO_LOCK(lock, &socket->mu);

  if (level == SOL_SOCKET && (option == SO_RCVBUF || option == SO_SNDBUF)) {
    return getsockopt_bufsize(socket, option, val, val_len);
  } else if (level == SOL_SOCKET && option == SO_RCVTIMEO) {
    return getsockopt_tvms(val, val_len, socket->recv_timeout_ms);
  } else if (level == SOL_SOCKET && option == SO_SNDTIMEO) {
    return getsockopt_tvms(val, val_len, socket->send_timeout_ms);
  } else if (level == SOL_SOCKET && option == SO_CONNECTTIMEO) {
    return getsockopt_tvms(val, val_len, socket->connect_timeout_ms);
  } else if (level == IPPROTO_TCP && option == SO_TCP_SEQ_NUM) {
    kspin_lock(&socket->spin_mu);
    if (socket->state != TCP_CLOSED) {
      kspin_unlock(&socket->spin_mu);
      return -EISCONN;
    }

    int seq = (int)socket->send_next;
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

  if (level == SOL_SOCKET && (option == SO_RCVBUF || option == SO_SNDBUF)) {
    return setsockopt_bufsize(socket, option, val, val_len);
  } else if (level == SOL_SOCKET && option == SO_RCVTIMEO) {
    return setsockopt_tvms(val, val_len, &socket->recv_timeout_ms);
  } else if (level == SOL_SOCKET && option == SO_SNDTIMEO) {
    return setsockopt_tvms(val, val_len, &socket->send_timeout_ms);
  } else if (level == SOL_SOCKET && option == SO_CONNECTTIMEO) {
    return setsockopt_tvms(val, val_len, &socket->connect_timeout_ms);
  } else if (level == IPPROTO_TCP && option == SO_TCP_SEQ_NUM) {
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
    socket->send_next = (uint32_t)seq;
    socket->send_unack = socket->send_next;
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
