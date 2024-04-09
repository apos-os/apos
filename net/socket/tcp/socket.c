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
#include "dev/interrupts.h"
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
#include "net/socket/sockopt.h"
#include "net/socket/tcp/congestion.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/protocol.h"
#include "net/socket/tcp/sockmap.h"
#include "net/socket/tcp/tcp.h"
#include "net/util.h"
#include "proc/defint.h"
#include "proc/kthread.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/spinlock.h"
#include "test/test_point.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/tcp.h"
#include "user/include/apos/vfs/vfs.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

#define DEFAULT_LISTEN_BACKLOG 10

#define SOCKET_DEFAULT_BUFSIZE (16 * 1024)

#define MAX_BUF_SIZE (1 * 1024 * 1024)

#define SOCKET_CONNECT_TIMEOUT_MS 60000

#define TCP_TIME_WAIT_MS 60000

#define TCP_DEFAULT_RTO_MS 1000
#define TCP_DEFAULT_MIN_RTO_MS 1000
#define TCP_MAX_RTO_MS 60000

#define TCP_WINDOW_UPDATE_DIVISOR 2

static const socket_ops_t g_tcp_socket_ops;

static short tcp_poll_events(const socket_tcp_t* socket);

static uint32_t gen_seq_num(const socket_tcp_t* sock) {
  return fnv_hash_concat(get_time_ms(), fnv_hash_addr((addr_t)sock));
}

static void set_iss(socket_tcp_t* socket, uint32_t iss) {
  KASSERT_DBG(socket->state == TCP_CLOSED);
  socket->initial_seq = iss;
  socket->send_next = socket->initial_seq;
  socket->send_unack = socket->send_next;
}

// Possibly updates the receive window if allowed by the SWS algorithm.  Returns
// true if the window was updated.  If `force` is true, the window is always
// updated.
static bool maybe_update_recv_window(socket_tcp_t* socket, bool force) {
  uint32_t threshold =
      min(socket->recv_buf.buflen / TCP_WINDOW_UPDATE_DIVISOR, socket->mss);
  uint32_t new_wnd = circbuf_available(&socket->recv_buf);
  if (new_wnd < socket->recv_wndsize ||
      circbuf_available(&socket->recv_buf) - socket->recv_wndsize >=
          threshold ||
      force) {
    KLOG(DEBUG2, "TCP: socket %p updated recv_wndsize %u -> %d bytes\n", socket,
         socket->recv_wndsize, new_wnd);
    socket->recv_wndsize = new_wnd;
    return true;
  }
  return false;
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
  kmemset(&sock->bind_addr, 0, sizeof(sock->bind_addr));
  kmemset(&sock->connected_addr, 0, sizeof(sock->connected_addr));
  sock->bind_addr.sa_family = AF_UNSPEC;
  sock->connected_addr.sa_family = AF_UNSPEC;
  circbuf_init(&sock->send_buf, sendbuf, SOCKET_DEFAULT_BUFSIZE);
  circbuf_init(&sock->recv_buf, recvbuf, SOCKET_DEFAULT_BUFSIZE);
  sock->recv_shutdown = false;
  sock->send_shutdown = false;
  sock->connect_timeout_ms = SOCKET_CONNECT_TIMEOUT_MS;
  sock->recv_timeout_ms = -1;
  sock->send_timeout_ms = -1;
  sock->tcp_flags = 0;
  set_iss(sock, gen_seq_num(sock));
  sock->iss_set = false;
  sock->recv_wndsize = circbuf_available(&sock->recv_buf);
  sock->mss = 536;  // TODO(tcp): determine MSS dynamically.
  tcp_cwnd_init(&sock->cwnd, sock->mss);
  sock->rto_ms = TCP_DEFAULT_RTO_MS;
  sock->rto_min_ms = TCP_DEFAULT_MIN_RTO_MS;
  sock->srtt_ms = -1;
  sock->rttvar = 0;
  sock->segments = LIST_INIT;
  sock->time_wait_ms = TCP_TIME_WAIT_MS;
  sock->syn_acked = false;
  kthread_queue_init(&sock->q);
  kmutex_init(&sock->mu);
  sock->spin_mu = KSPINLOCK_NORMAL_INIT;
  poll_init_event(&sock->poll_event);
  sock->timer = TIMER_HANDLE_NONE;

  sock->max_accept = sock->queued = 0;
  sock->children_connecting = LIST_INIT;
  sock->children_established = LIST_INIT;
  sock->parent = NULL;
  sock->link = LIST_LINK_INIT;

  *out = &(sock->base);
  return 0;
}

socktcp_state_type_t tcp_state_type(socktcp_state_t s) {
  switch (s) {
    case TCP_CLOSED:
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RCVD:
      return TCPSTATE_PRE_ESTABLISHED;

    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
      return TCPSTATE_ESTABLISHED;

    case TCP_LAST_ACK:
    case TCP_CLOSED_DONE:
    case TCP_CLOSING:
    case TCP_TIME_WAIT:
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
    CONSIDER(LISTEN)
    CONSIDER(SYN_SENT)
    CONSIDER(SYN_RCVD)
    CONSIDER(ESTABLISHED)
    CONSIDER(CLOSE_WAIT)
    CONSIDER(LAST_ACK)
    CONSIDER(FIN_WAIT_1)
    CONSIDER(FIN_WAIT_2)
    CONSIDER(CLOSING)
    CONSIDER(TIME_WAIT)
  }
#undef CONSIDER
  KLOG(FATAL, "Unknown TCP state %d\n", state);
  return "UNKNOWN";
}

static void tcp_wake(socket_tcp_t* sock) {
  scheduler_wake_all(&sock->q);
  poll_trigger_event(&sock->poll_event, tcp_poll_events(sock));
}

static void set_state(socket_tcp_t* sock, socktcp_state_t new_state,
                      const char* debug_msg) {
  KASSERT(kspin_is_held(&sock->spin_mu));
  KLOG(DEBUG2, "TCP: socket %p state %s -> %s (%s)\n", sock,
       state2str(sock->state), state2str(new_state), debug_msg);
  sock->state = new_state;
  if (new_state == TCP_TIME_WAIT) {
    KASSERT_DBG(sock->connected_addr.sa_family != AF_UNSPEC);
    tcpsm_mark_reusable(&g_tcp.sockets, &sock->bind_addr, &sock->connected_addr,
                        sock);
  }
  // Wake up anyone waiting for a state transition.
  tcp_wake(sock);
}

static void delete_socket(socket_tcp_t* socket) {
  KASSERT_DBG(socket->ref.ref == 0);
  KASSERT_DBG(socket->parent == NULL);
  KASSERT_DBG(socket->state == TCP_CLOSED_DONE);
  KASSERT_DBG(socket->timer == TIMER_HANDLE_NONE);
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

static void tcp_set_timer(socket_tcp_t* socket, int duration_ms, bool force);
static void tcp_cancel_timer(socket_tcp_t* socket);

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

// Transmit a constructed segment.  Requires the socket be locked, but unlocks
// it before calculating the checksum and transmitting.
static int tcp_transmit_segment(socket_tcp_t* socket,
                                const ip4_pseudo_hdr_t* pseudo_ip,
                                tcp_segment_t* seg,
                                pbuf_t* pb,
                                bool allow_block) {
  seg->retransmits = 0;
  seg->tx_time = get_time_ms();
  list_push(&socket->segments, &seg->link);
  tcp_set_timer(socket, socket->rto_ms, false);
  kspin_unlock(&socket->spin_mu);

  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  KASSERT_DBG(tcp_hdr->flags == seg->flags);
  tcp_hdr->checksum = ip_checksum2(pseudo_ip, sizeof(ip4_pseudo_hdr_t),
                                   pbuf_get(pb), pbuf_size(pb));

  ip4_add_hdr(pb, pseudo_ip->src_addr, pseudo_ip->dst_addr, IPPROTO_TCP);
  return ip_send(pb, allow_block);
}

static void tcp_retransmit_segment(socket_tcp_t* socket, tcp_segment_t* seg) {
  KASSERT(!list_empty(&socket->segments));
  KASSERT(socket->state != TCP_CLOSED_DONE);
  if (seg->retransmits == 0) {
    uint32_t unacked_bytes = socket->send_next - socket->send_unack;
    tcp_cwnd_loss(&socket->cwnd, unacked_bytes);
  }
  seg->retransmits++;

  ip4_pseudo_hdr_t pseudo_ip;
  pbuf_t* pb = NULL;
  int result = tcp_build_segment(socket, seg, &pb, &pseudo_ip);
  if (result < 0) {
    KLOG(DFATAL,
         "TCP: socket %p unable to reconstruct segment to retransmit: %s\n",
         socket, errorname(-result));
    kspin_unlock(&socket->spin_mu);
    return;
  }

  kspin_unlock(&socket->spin_mu);

  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  KASSERT_DBG(tcp_hdr->flags == seg->flags);
  tcp_hdr->checksum = ip_checksum2(&pseudo_ip, sizeof(ip4_pseudo_hdr_t),
                                   pbuf_get(pb), pbuf_size(pb));

  ip4_add_hdr(pb, pseudo_ip.src_addr, pseudo_ip.dst_addr, IPPROTO_TCP);
  result = ip_send(pb, /* allow_block */ false);

  if (result < 0) {
    KLOG(WARNING, "TCP: socket %p unable to retransmit packet: %s\n", socket,
         errorname(-result));
  }
}

// Sends a SYN (and updates socket->send_next).
static int tcp_send_syn(socket_tcp_t* socket, bool ack, bool allow_block) {
  kspin_lock(&socket->spin_mu);
  KASSERT(socket->state == TCP_SYN_SENT || socket->state == TCP_SYN_RCVD);

  tcp_segment_t* seg = KMALLOC(tcp_segment_t);
  tcp_syn_segment(socket, seg, ack);

  ip4_pseudo_hdr_t pseudo_ip;
  pbuf_t* pb = NULL;
  int result = tcp_build_segment(socket, seg, &pb, &pseudo_ip);
  if (result < 0) {
    if (result != -EAGAIN) {
      KLOG(DFATAL, "TCP: unable to create SYN packet: %s\n",
           errorname(-result));
    }
    kspin_unlock(&socket->spin_mu);
    kfree(seg);
    return result;
  }
  // If this is our first time sending the SYN, advance send_next.
  if (socket->send_next == socket->initial_seq) {
    socket->send_next++;
  }

  KLOG(DEBUG2, "TCP: socket %p transmitting SYN%s\n", socket,
       ack ? "/ACK" : "");
  return tcp_transmit_segment(socket, &pseudo_ip, seg, pb, allow_block);
}

// Sends data and/or a FIN if available.  If no data is ready to be sent,
// returns -EAGAIN (and doesn't send any packets).
static int tcp_send_datafin(socket_tcp_t* socket, bool allow_block) {
  // Figure out how much data to send.
  kspin_lock(&socket->spin_mu);
  if (tcp_state_type(socket->state) != TCPSTATE_ESTABLISHED &&
      socket->state != TCP_SYN_RCVD) {
    kspin_unlock(&socket->spin_mu);
    return -EAGAIN;
  }

  // In SYN_RCVD, only allowed to send FINs, not data.
  if (socket->state == TCP_SYN_RCVD && socket->send_buf.len > 0) {
    kspin_unlock(&socket->spin_mu);
    return -EAGAIN;
  }

  tcp_segment_t* seg = KMALLOC(tcp_segment_t);
  tcp_next_segment(socket, seg);
  ip4_pseudo_hdr_t pseudo_ip;
  pbuf_t* pb = NULL;
  int result = tcp_build_segment(socket, seg, &pb, &pseudo_ip);
  if (result) {
    if (result != -EAGAIN) {
      KLOG(DFATAL, "TCP: unable to create data/FIN packet: %s\n",
           errorname(-result));
    }
    kspin_unlock(&socket->spin_mu);
    kfree(seg);
    return result;
  }
  socket->send_next += seg->data_len;
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  bool sent_fin = (tcp_hdr->flags & TCP_FLAG_FIN);
  if (sent_fin) {
    socket->send_next++;
    switch (socket->state) {
      case TCP_CLOSE_WAIT:
        set_state(socket, TCP_LAST_ACK, "sending FIN");
        break;

      case TCP_ESTABLISHED:
        set_state(socket, TCP_FIN_WAIT_1, "sending FIN");
        break;

      case TCP_SYN_RCVD:
        set_state(socket, TCP_FIN_WAIT_1, "sending FIN");
        break;

      case TCP_CLOSED_DONE:
      case TCP_LISTEN:
      case TCP_LAST_ACK:
      case TCP_CLOSED:
      case TCP_SYN_SENT:
      case TCP_FIN_WAIT_1:
      case TCP_FIN_WAIT_2:
      case TCP_CLOSING:
      case TCP_TIME_WAIT:
        KLOG(DFATAL, "TCP: socket %p sent FIN in invalid state %s\n", socket,
             state2str(socket->state));
        break;
    }
  }
  KLOG(DEBUG2, "TCP: socket %p transmitting %s%zu bytes of data\n", socket,
       sent_fin ? "FIN and " : "", seg->data_len);
  return tcp_transmit_segment(socket, &pseudo_ip, seg, pb, allow_block);
}

static bool tcp_dispatch_to_sock(socket_tcp_t* socket, const pbuf_t* pb,
                                 const tcp_packet_metadata_t* md);

// Dispatches the packet to the socket (which could be NULL), or sends a RST.
// Always consumes the packet.
static void tcp_dispatch_or_rst(socket_tcp_t* socket, pbuf_t* pb,
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

  // Find a matching socket.
  kspin_lock(&g_tcp.lock);
  socket_tcp_t* socket = tcpsm_find(&g_tcp.sockets, &mdata.dst, &mdata.src);
  if (socket) {
    refcount_inc(&socket->ref);
  }
  kspin_unlock(&g_tcp.lock);

  if (socket) {
    tcp_dispatch_or_rst(socket, pb, &mdata);
    TCP_DEC_REFCOUNT(socket);
    return true;
  }

  // Incoming packet didn't match any listeners.  Restore the original IP header
  // and return to the IP stack (in case any raw sockets want it).
  // TODO(tcp): send a RST?
  // Restore the original IP header.
  pbuf_push_header(pb, mdata.ip_hdr_len);

  return false;
}

static void tcp_dispatch_or_rst(socket_tcp_t* socket, pbuf_t* pb,
                                const tcp_packet_metadata_t* md) {
  bool handled = false;
  if (socket) {
    handled = tcp_dispatch_to_sock(socket, pb, md);
  }

  if (!handled) {
    tcp_send_raw_rst(pb, md);
  }
  pbuf_free(pb);
}

// Terminal actions for a packet.  These are mutually exclusive.
typedef enum {
  TCP_ACTION_NOT_SET = 0,  // No terminal action set --- continue processing.
  TCP_ACTION_NONE,         // No specific action to take.
  TCP_DROP_BAD_PKT,        // Drop the packet, it is bad.
  TCP_SEND_RAW_RST,        // Send a RST without resetting the connection.
  TCP_RESET_CONNECTION,    // Send a RST and reset the connection.
  TCP_RETRANSMIT,          // Retransmit the first (oldest) segment.
} tcp_pkt_terminal_action_t;

// Action to take based on a packet.
typedef struct {
  tcp_pkt_terminal_action_t action;
  bool send_ack;  // Whether to send an ACK in addition to the action.
} tcp_pkt_action_t;

// Handlers for different types of packet scenarios.  Multiple of these may be
// called for a particular incoming packet depending on its contents.

// Specific handler for SYN_SENT and LISTEN states.
static void tcp_handle_in_synsent(socket_tcp_t* socket, const pbuf_t* pb,
                                  tcp_pkt_action_t* action);
static void tcp_handle_in_listen(socket_tcp_t* socket, const pbuf_t* pb,
                                 const tcp_packet_metadata_t* md);

// Special case for maybe handling a retransmitted FIN in TIME_WAIT.
static void maybe_handle_time_wait_fin(socket_tcp_t* socket, const pbuf_t* pb,
                                       const tcp_packet_metadata_t* md,
                                       uint32_t seq);

static void tcp_handle_syn(socket_tcp_t* socket, const pbuf_t* pb,
                           tcp_pkt_action_t* action);
static void tcp_handle_ack(socket_tcp_t* socket, const pbuf_t* pb,
                           tcp_pkt_action_t* action);
static void tcp_handle_fin(socket_tcp_t* socket, const pbuf_t* pb,
                           const tcp_packet_metadata_t* md,
                           tcp_pkt_action_t* action);
static void tcp_handle_rst(socket_tcp_t* socket, const pbuf_t* pb,
                           tcp_pkt_action_t* action);
static void tcp_handle_data(socket_tcp_t* socket, const pbuf_t* pb,
                            const tcp_packet_metadata_t* md,
                            tcp_pkt_action_t* action);

static void finish_protocol_close(socket_tcp_t* socket, const char* reason);

static void tcp_timer_cb(void* arg);
static void tcp_timer_defint(void* arg);
static void handle_retransmit_timer(socket_tcp_t* socket);

// Updates the current TCP timer.  If the timer is currently set, only updates
// the timer if force == true.  If no timer is running, always creates.
static void tcp_set_timer(socket_tcp_t* socket, int duration_ms, bool force) {
  apos_ms_t deadline = get_time_ms() + duration_ms;
  KASSERT(kspin_is_held(&socket->spin_mu));
  PUSH_AND_DISABLE_INTERRUPTS();
  if (socket->timer != TIMER_HANDLE_NONE && force) {
    cancel_event_timer(socket->timer);
    socket->timer = TIMER_HANDLE_NONE;
  }
  if (socket->timer == TIMER_HANDLE_NONE) {
    register_event_timer(deadline, &tcp_timer_cb, socket, &socket->timer);
    socket->timer_deadline = deadline;
  }
  POP_INTERRUPTS();
}

// Cancels the current TCP timer, if any.
static void tcp_cancel_timer(socket_tcp_t* socket) {
  KASSERT(kspin_is_held(&socket->spin_mu));
  PUSH_AND_DISABLE_INTERRUPTS();
  if (socket->timer != TIMER_HANDLE_NONE) {
    cancel_event_timer(socket->timer);
    socket->timer = TIMER_HANDLE_NONE;
  }
  socket->timer_deadline = APOS_MS_MAX;
  POP_INTERRUPTS();
}

static void tcp_timer_cb(void* arg) {
  socket_tcp_t* socket = arg;
  socket->timer = TIMER_HANDLE_NONE;
  refcount_inc(&socket->ref);
  defint_schedule(&tcp_timer_defint, socket);
}

static void tcp_timer_defint(void* arg) {
  socket_tcp_t* socket = arg;
  kspin_lock(&socket->spin_mu);
  if (socket->state == TCP_CLOSED_DONE) {
    KLOG(DEBUG, "TCP: socket %p ignoring timer post-close\n", socket);
    kspin_unlock(&socket->spin_mu);
    TCP_DEC_REFCOUNT(socket);
    return;
  }

  // If the next timer is set in the future, this is a spurious timer and
  // should be ignored.
  if (socket->timer_deadline > get_time_ms()) {
    KLOG(DEBUG, "TCP: socket %p ignoring spurious timer\n", socket);
    kspin_unlock(&socket->spin_mu);
    TCP_DEC_REFCOUNT(socket);
    return;
  }

  if (socket->state == TCP_TIME_WAIT) {
    finish_protocol_close(socket, "TIME_WAIT finished");
    kspin_unlock(&socket->spin_mu);
  } else {
    handle_retransmit_timer(socket);
    // handle_retransmit_timer() handles the unlock.
  }

  TCP_DEC_REFCOUNT(socket);
}

static void handle_retransmit_timer(socket_tcp_t* socket) {
  if (list_empty(&socket->segments)) {
    KLOG(DFATAL, "TCP: socket %p fired RTO timer but has no segments\n",
         socket);
    kspin_unlock(&socket->spin_mu);
    return;
  }

  // Possibly configurations of segment seq and socket->send_unack:
  //    u     |   <-- typical (send_unack aligned with unack'd segment)
  //    |  u  |   <-- atypical (segment partially ack'd)
  // u  |     |   <-- not allowed (we're missing a segment)
  //    |     | u <-- not allowed (segment was fully ack'd)

  tcp_segment_t* seg = container_of(socket->segments.head, tcp_segment_t, link);
  uint32_t seg_len = tcp_seg_len(seg);
  KASSERT_DBG(seq_ge(socket->send_unack, seg->seq));
  KASSERT_DBG(seq_lt(socket->send_unack, seg->seq + seg_len));

  // If part of the segment was acknowledged, for some reason, truncate this
  // segment to only retransmit the unacked portion.
  if (seg->seq != socket->send_unack) {
    uint32_t bytes_trunc = (socket->send_unack - seg->seq);
    KLOG(DEBUG,
         "TCP: socket %p truncating partially-acked segment for retransmit "
         "(seq %u -> %d; %u bytes less)\n",
         socket, seg->seq - socket->initial_seq,
         socket->send_unack - socket->initial_seq, bytes_trunc);
    seg->seq = socket->send_unack;
    seg->data_len -= bytes_trunc;
    KASSERT_DBG(!(seg->flags & TCP_FLAG_SYN));  // Could support this if needed.
  }

  socket->rto_ms = min(socket->rto_ms * 2, TCP_MAX_RTO_MS);
  KLOG(DEBUG,
       "TCP: socket %p retransmitting segment [%u, %u) (retransmits: %d); RTO "
       "-> %dms\n",
       socket, seg->seq - socket->initial_seq,
       seg->seq + seg_len - socket->initial_seq, seg->retransmits,
       socket->rto_ms);

  tcp_set_timer(socket, socket->rto_ms, /* force */ true);
  tcp_retransmit_segment(socket, seg);  // Unlocks the socket.
}

// Resets the connection state, but does _not_ set a socket error or send a RST.
static void reset_connection(socket_tcp_t* socket, const char* reason);

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
  tcp_pkt_action_t action;
  action.action = TCP_ACTION_NOT_SET;
  action.send_ack = false;

  test_point_run("tcp:dispatch_packet");

  kspin_lock(&socket->spin_mu);

  // TCP_CLOSED can happen if we receive a packet for an address that a socket
  // is bound to, but is not listening on (or connected on).  TCP_CLOSED_DONE
  // can happen if the socket closes right after we take it out of the socket
  // map, but before we lock it.
  if (socket->state == TCP_CLOSED || socket->state == TCP_CLOSED_DONE) {
    KLOG(DEBUG, "TCP: socket %p received packet in CLOSED; sending RST\n",
         socket);
    kspin_unlock(&socket->spin_mu);
    return false;
  }

  // If in LISTEN, tcp_handle_in_listen() takes care of everything (including
  // unlocking the socket!)
  if (socket->state == TCP_LISTEN) {
    tcp_handle_in_listen(socket, pb, md);
    return true;
  }

  if (socket->state == TCP_SYN_SENT) {
    tcp_handle_in_synsent(socket, pb, &action);
    goto done;
  }

  // Check the sequence number of the packet.  The packet must overlap with the
  // receive window.
  uint32_t seq = btoh32(tcp_hdr->seq);
  if (!validate_seq(socket, seq, tcp_packet_octets(tcp_hdr, md))) {
    // Special case for FIN in TIME_WAIT.
    if (socket->state == TCP_TIME_WAIT) {
      maybe_handle_time_wait_fin(socket, pb, md, seq);
    }
    KLOG(DEBUG2, "TCP: socket %p got out-of-window packet, dropping\n", socket);
    action.action = TCP_DROP_BAD_PKT;
    action.send_ack = !(tcp_hdr->flags & TCP_FLAG_RST);
    goto done;
  }

  if (seq_gt(seq, socket->recv_next)) {
    KLOG(DEBUG2,
         "TCP: socket %p dropping OOO packet (past start of window)\n",
         socket);
    action.send_ack = true;
    goto done;
  }

  if (tcp_hdr->flags & TCP_FLAG_RST) {
    tcp_handle_rst(socket, pb, &action);
    // We should always be done after a RST.
    goto done;
  }

  // Next handle SYN and SYN-ACK.
  if (tcp_hdr->flags & TCP_FLAG_SYN) {
    tcp_handle_syn(socket, pb, &action);
    if (action.action != TCP_ACTION_NOT_SET) {
      goto done;
    }
  }

  if (!(tcp_hdr->flags & TCP_FLAG_ACK)) {
    KLOG(INFO, "TCP: socket %p dropping packet without ACK\n", socket);
    action.action = TCP_DROP_BAD_PKT;
    goto done;
  }

  tcp_handle_ack(socket, pb, &action);
  if (action.action != TCP_ACTION_NOT_SET) {
    goto done;
  }

  if (tcp_hdr->flags & TCP_FLAG_URG) {
    KLOG(DEBUG, "TCP: socket %p cannot handle URG data\n", socket);
    socket->error = ECONNRESET;
    action.action = TCP_RESET_CONNECTION;
    goto done;
  }

  if (md->data_len > 0) {
    tcp_handle_data(socket, pb, md, &action);
    if (action.action != TCP_ACTION_NOT_SET) {
      goto done;
    }
  }

  if (tcp_hdr->flags & TCP_FLAG_FIN) {
    tcp_handle_fin(socket, pb, md, &action);
  }

done:
  kspin_unlock(&socket->spin_mu);
  test_point_run("tcp:dispatch_packet_action");

  int result = 0;
  switch (action.action) {
    case TCP_DROP_BAD_PKT:
      KLOG(DEBUG2, "TCP: socket %p dropping bad packet\n", socket);
      break;

    case TCP_SEND_RAW_RST:
      result = tcp_send_raw_rst(pb, md);
      if (result != 0) {
        KLOG(WARNING, "TCP: socket %p unable to send raw RST: %s\n", socket,
             errorname(-result));
      }
      break;

    case TCP_RESET_CONNECTION:
      result = tcp_send_rst(socket);
      if (result != 0) {
        KLOG(WARNING, "TCP: socket %p unable to send RST: %s\n", socket,
             errorname(-result));
      }
      kspin_lock(&socket->spin_mu);
      reset_connection(socket, "Resetting connection");
      kspin_unlock(&socket->spin_mu);
      break;

    case TCP_RETRANSMIT:
      kspin_lock(&socket->spin_mu);
      if (socket->state == TCP_CLOSED_DONE) {
        KLOG(DEBUG3, "TCP: socket %p closed before retransmit\n", socket);
        kspin_unlock(&socket->spin_mu);
        return true;
      }
      if (list_empty(&socket->segments)) {
        KLOG(DFATAL, "TCP: socket %p cannot retransmit, no segments\n", socket);
        kspin_unlock(&socket->spin_mu);
        return true;
      }
      tcp_segment_t* seg =
          container_of(socket->segments.head, tcp_segment_t, link);
      tcp_retransmit_segment(socket, seg);  // Handles socket unlock.
      break;

    case TCP_ACTION_NOT_SET:
    case TCP_ACTION_NONE:
      result = tcp_send_datafin(socket, false);
      if (result == 0) {
        action.send_ack = false;  // We sent data, that includes an ack
      } else if (result != -EAGAIN) {
        KLOG(WARNING, "TCP: socket %p unable to send data: %s\n", socket,
             errorname(-result));
      }
  }

  if (action.send_ack) {
    result = tcp_send_ack(socket);
    if (result != 0) {
      KLOG(WARNING, "TCP: socket %p unable to send ACK: %s\n", socket,
           errorname(-result));
    }
  }

  return true;
}

static void tcp_handle_syn(socket_tcp_t* socket, const pbuf_t* pb,
                           tcp_pkt_action_t* action) {
  // If we get a SYN in any state other than SYN_SENT, just send an ack and
  // otherwise ignore it.
  KLOG(DEBUG2, "TCP: socket %p got SYN in state %s\n", socket,
       state2str(socket->state));
  action->action = TCP_ACTION_NONE;
  action->send_ack = true;
}

bool tcp_is_fin_sent(socktcp_state_t state) {
  switch (state) {
    case TCP_CLOSED:
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RCVD:
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
    case TCP_CLOSED_DONE:
      return false;

    case TCP_LAST_ACK:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_CLOSING:
    case TCP_TIME_WAIT:
      return true;
  }
  KLOG(DFATAL, "TCP: invalid socket state %d\n", (int)state);
  return false;
}

static void syn_rcvd_connected(socket_tcp_t* socket) {
  set_state(socket, TCP_ESTABLISHED, "SYN ack'd");
  if (socket->parent) {
    kspin_lock(&socket->parent->spin_mu);
    if (socket->parent->state == TCP_LISTEN) {
      list_remove(&socket->parent->children_connecting, &socket->link);
      list_push(&socket->parent->children_established, &socket->link);
      tcp_wake(socket->parent);
    } else {
      KASSERT_DBG(socket->parent->state == TCP_CLOSED_DONE);
    }
    kspin_unlock(&socket->parent->spin_mu);
  }
}

static void segment_acked(socket_tcp_t* socket, tcp_segment_t* seg,
                          uint32_t seg_len) {
  if (seg->retransmits == 0) {
    int rtt_ms = get_time_ms() - seg->tx_time;
    KASSERT_DBG(rtt_ms >= 0);
    if (socket->srtt_ms < 0) {
      // First measurement.
      socket->srtt_ms = rtt_ms;
      socket->rttvar = rtt_ms / 2;
    } else {
      // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
      socket->rttvar =
          3 * (socket->rttvar / 4) + abs(socket->srtt_ms - rtt_ms) / 4;
      // SRTT <- (1 - alpha) * SRTT + alpha * R'
      socket->srtt_ms = 7 * (socket->srtt_ms / 8) + rtt_ms / 8;
    }
    // RTO <- SRTT + max (G, K*RTTVAR)
    int old_rto = socket->rto_ms;
    socket->rto_ms = socket->srtt_ms + max(KTIMESLICE_MS, 4 * socket->rttvar);
    socket->rto_ms = max(socket->rto_ms, socket->rto_min_ms);
    socket->rto_ms = min(socket->rto_ms, TCP_MAX_RTO_MS);
    KLOG(DEBUG3,
         "TCP: socket %p segment RTT: %dms -> "
         "SRTT %dms; RTTVAR %dms; RTO %dms -> %dms\n",
         socket, rtt_ms, socket->srtt_ms, socket->rttvar, old_rto,
         socket->rto_ms);
  }
  KLOG(DEBUG3, "TCP: socket %p retired segment [%u, %u) (retransmits: %d)\n",
       socket, seg->seq - socket->initial_seq,
       seg->seq + seg_len - socket->initial_seq, seg->retransmits);

  if ((seg->flags & TCP_FLAG_SYN) && seg->retransmits > 0) {
    KLOG(DEBUG, "TCP: socket %p retransmitted SYN; RTO set to 3s\n", socket);
    socket->rto_ms = 3000;
  }
}

static void tcp_handle_ack(socket_tcp_t* socket, const pbuf_t* pb,
                           tcp_pkt_action_t* action) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(tcp_hdr->flags & TCP_FLAG_ACK);

  // TODO(tcp): send retransmits on duplicate ACKs.
  uint32_t ack = btoh32(tcp_hdr->ack);
  if (seq_gt(ack, socket->send_next)) {
    KLOG(DEBUG2, "TCP: socket %p got future ACK (ack=%u)\n", socket, ack);
    action->action = TCP_DROP_BAD_PKT;
    action->send_ack = true;
    return;
  } else if (seq_lt(ack, socket->send_unack)) {
    KLOG(DEBUG2, "TCP: socket %p got duplicate ACK (ack=%u)\n", socket, ack);
    return;
  }

  // Consume ack'd segments.
  int segs_acked = 0;
  while (!list_empty(&socket->segments)) {
    tcp_segment_t* seg =
        container_of(socket->segments.head, tcp_segment_t, link);
    uint32_t seg_len = tcp_seg_len(seg);
    if (seq_gt(seg->seq + seg_len, ack)) {
      break;
    }

    segs_acked++;
    segment_acked(socket, seg, seg_len);
    list_pop(&socket->segments);
    kfree(seg);
  }

  if (list_empty(&socket->segments) && socket->state != TCP_TIME_WAIT) {
    tcp_cancel_timer(socket);
  } else if (segs_acked > 0) {
    tcp_set_timer(socket, socket->rto_ms, true);
  }

  uint32_t seqs_acked = ack - socket->send_unack;
  uint32_t bytes_acked = seqs_acked;
  // We need to track syn_acked explicitly due to the possibility of wraparound.
  if (bytes_acked > 0 && !socket->syn_acked) {
    KASSERT_DBG(socket->send_unack == socket->initial_seq);
    socket->syn_acked = true;
    bytes_acked--;  // Account for the SYN.
  }
  if (seqs_acked > 0 && tcp_is_fin_sent(socket->state) &&
      ack == socket->send_next) {
    bytes_acked--;  // Account for the FIN.
  }

  ssize_t consumed = circbuf_consume(&socket->send_buf, bytes_acked);
  socket->send_buf_seq += consumed;
  if (consumed != (int)bytes_acked) {
    KLOG(DFATAL, "TCP: unable to consume all ACK'd bytes\n");
    return;
  }
  // TODO(tcp): handle window updates properly (track WL1/WL2).
  socket->send_unack = ack;
  socket->send_wndsize = btoh16(tcp_hdr->wndsize);
  if (bytes_acked > 0) {
    tcp_cwnd_acked(&socket->cwnd, bytes_acked);
  }
  KLOG(DEBUG2,
       "TCP: socket %p had %u octets acked (data bytes acked: %u; remaining "
       "unacked: %u; send_wndsize: %d; cwnd: %u)\n",
       socket, seqs_acked, bytes_acked, socket->send_next - socket->send_unack,
       socket->send_wndsize, socket->cwnd.cwnd);
  tcp_wake(socket);

  switch (socket->state) {
    case TCP_LAST_ACK:
      // If our FIN is acked, finish closing.
      if (socket->send_unack == socket->send_next) {
        finish_protocol_close(socket, "socket closed");
      }
      break;

    case TCP_SYN_RCVD:
      // If our SYN is acked, move to ESTABLISHED.
      if (socket->send_unack == socket->send_next) {
        syn_rcvd_connected(socket);
      }
      break;

    case TCP_FIN_WAIT_1:
      // If our FIN is acked, move to FIN_WAIT_2.
      if (socket->send_unack == socket->send_next) {
        set_state(socket, TCP_FIN_WAIT_2, "FIN ack'd");
      }
      break;

    case TCP_CLOSING:
      // If our FIN is acked, move to TIME_WAIT.
      if (socket->send_unack == socket->send_next) {
        set_state(socket, TCP_TIME_WAIT, "FIN ack'd");
        tcp_set_timer(socket, socket->time_wait_ms, /* force */ true);
      }
      break;

    case TCP_FIN_WAIT_2:
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
    case TCP_TIME_WAIT:
      // Nothing to do, rely on common ACK handling above.
      break;

    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
    case TCP_SYN_SENT:
    case TCP_LISTEN:
      KLOG(DFATAL, "TCP: socket %p packet received in invalid state\n", socket);
      break;
  }
}

static void tcp_handle_fin(socket_tcp_t* socket, const pbuf_t* pb,
                           const tcp_packet_metadata_t* md,
                           tcp_pkt_action_t* action) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));

  // Check if the FIN is in the socket's receive window.
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  uint32_t fin_seq = btoh32(tcp_hdr->seq) + (uint32_t)md->data_len;
  if (seq_ge(fin_seq, socket->recv_next + socket->recv_wndsize)) {
    KLOG(DEBUG2, "TCP: socket %p ignoring out-of-window FIN\n", socket);
    return;
  }

  KLOG(DEBUG2, "TCP: socket %p received FIN\n", socket);

  switch (socket->state) {
    case TCP_ESTABLISHED:
      set_state(socket, TCP_CLOSE_WAIT, "FIN received");
      socket->recv_next++;
      action->send_ack = true;
      return;

    case TCP_LAST_ACK:
    case TCP_CLOSE_WAIT:
    case TCP_CLOSING:
    case TCP_TIME_WAIT:
      // N.B.(aoates): ostensibly if we get a new FIN in TIME_WAIT, we're
      // supposed to restart the timer.  But that should only happen (here) if
      // we receive a FIN with a seqno immediately after the "true" FIN we
      // already received (if before, would be treated as a retransmition and
      // handled earlier; if after, would be outside of window and dropped).

      // Nothing to do, stay in same state.
      return;

    case TCP_FIN_WAIT_1:
      // If send_unack had caught up to send_next, that means our FIN was ACK'd,
      // and we should have entered FIN_WAIT_2 in tcp_handle_ack() above.
      KASSERT_DBG(seq_lt(socket->send_unack, socket->send_next));
      set_state(socket, TCP_CLOSING, "simultaneous close (got FIN, no ACK)");
      socket->recv_next++;
      action->send_ack = true;
      return;

    case TCP_FIN_WAIT_2:
      set_state(socket, TCP_TIME_WAIT, "FIN received");
      socket->recv_next++;
      action->send_ack = true;
      tcp_set_timer(socket, socket->time_wait_ms, /* force */ true);
      return;

    case TCP_SYN_RCVD:
      // This can happen if e.g. we get a valid FIN but our SYN hasn't been
      // acknowledged yet (and therefore we haven't moved into ESTABLISHED).
      KLOG(DEBUG2, "TCP: socket %p ignoring FIN received in SYN_RCVD\n",
           socket);
      action->action = TCP_DROP_BAD_PKT;
      return;

    case TCP_SYN_SENT:
    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
    case TCP_LISTEN:
      KLOG(DFATAL, "TCP: socket %p FIN received in invalid state\n", socket);
      action->action = TCP_DROP_BAD_PKT;
      return;
  }
  KLOG(FATAL, "TCP: socket %p in invalid state %d\n", socket, socket->state);
}

static void tcp_handle_rst(socket_tcp_t* socket, const pbuf_t* pb,
                           tcp_pkt_action_t* action) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  KLOG(DEBUG, "TCP: socket %p received RST\n", socket);

  // This is required for packets that otherwise are valid (e.g. have data that
  // overlaps the window), and have RST set, but are not window-aligned.
  if (btoh32(tcp_hdr->seq) != socket->recv_next) {
    // If greater than recv_next, should have been caught before.
    KASSERT_DBG(seq_lt(btoh32(tcp_hdr->seq), socket->recv_next));
    KLOG(DEBUG, "TCP: socket %p out-of-order RST, dropping\n", socket);
    action->action = TCP_DROP_BAD_PKT;
    return;
  }

  // Reset the connection.
  switch (socket->state) {
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
      socket->error = ECONNRESET;
      reset_connection(socket, "connection reset");
      action->action = TCP_ACTION_NONE;
      return;

    case TCP_LAST_ACK:
    case TCP_CLOSING:
    case TCP_TIME_WAIT:
      // Don't clear the read buffer here --- let any pending data be consumed
      // (since we're not signalling an error).
      KASSERT_DBG(socket->send_shutdown);
      KASSERT_DBG(socket->send_buf.len == 0);
      finish_protocol_close(socket, "connection reset (already closed)");
      action->action = TCP_ACTION_NONE;
      return;

    case TCP_SYN_RCVD:
      socket->error = ECONNREFUSED;
      reset_connection(socket, "connection refused");
      action->action = TCP_ACTION_NONE;
      return;

    case TCP_SYN_SENT:
    case TCP_CLOSED:
    case TCP_CLOSED_DONE:
    case TCP_LISTEN:
      die("RST handling in invalid state");
  }
  KLOG(FATAL, "TCP: socket %p in invalid state %d\n", socket, socket->state);
}

static void tcp_handle_data(socket_tcp_t* socket, const pbuf_t* pb,
                            const tcp_packet_metadata_t* md,
                            tcp_pkt_action_t* action) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);

  // Trim the packet to fit in the window.
  uint32_t seq = btoh32(tcp_hdr->seq);
  size_t trim_start = 0, trim_end = 0;
  KASSERT_DBG(seq_le(seq, socket->recv_next));
  if (seq_lt(seq, socket->recv_next)) {
    trim_start = socket->recv_next - seq;
  }
  KASSERT_DBG(md->data_len >= trim_start);
  if (md->data_len - trim_start > socket->recv_wndsize) {
    trim_end = md->data_len - trim_start - socket->recv_wndsize;
  }
  KASSERT_DBG(md->data_len - trim_start - trim_end <= socket->recv_wndsize);

  if (trim_start > 0 || trim_end > 0) {
    KLOG(DEBUG2,
         "TCP: socket %p trimmed packet (%zu bytes at start, %zu bytes at "
         "end)\n", socket, trim_start, trim_end);
  }

  size_t data_offset = md->data_offset + trim_start;
  size_t data_len = md->data_len - trim_start - trim_end;
  if (data_len == 0) {
    KLOG(DEBUG2, "TCP: socket %p trimmed all data away\n", socket);
    return;
  }

  if (socket->state != TCP_ESTABLISHED && socket->state != TCP_FIN_WAIT_1 &&
      socket->state != TCP_FIN_WAIT_2) {
    KLOG(DEBUG2,
         "TCP: socket %p ignoring %d bytes of data in non-connected state %s\n",
         socket, (int)md->data_len, state2str(socket->state));
    action->action = TCP_DROP_BAD_PKT;
    return;
  }

  if (socket->recv_shutdown) {
    KLOG(DEBUG2, "TCP: socket %p got data after shutdown(RD), sending RST\n",
         socket);
    action->action = TCP_RESET_CONNECTION;
    return;
  }

  KASSERT_DBG(data_len <= pbuf_size(pb) - data_offset);
  ssize_t bytes_read = circbuf_write(
      &socket->recv_buf, pbuf_getc(pb) + data_offset, data_len);
  KASSERT(bytes_read >= 0);
  KLOG(DEBUG2, "TCP: socket %p received %d bytes of data\n", socket,
       (int)bytes_read);

  socket->recv_next += bytes_read;
  maybe_update_recv_window(socket, /* force */ false);
  tcp_wake(socket);
  action->send_ack = true;
}

static void tcp_handle_in_synsent(socket_tcp_t* socket, const pbuf_t* pb,
                                  tcp_pkt_action_t* action) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));

  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    uint32_t seg_ack = btoh32(tcp_hdr->ack);
    // We don't transit data with our SYN, so this is the only acceptable ACK.
    if (seg_ack != socket->send_next) {
      if (tcp_hdr->flags & TCP_FLAG_RST) {
        action->action = TCP_ACTION_NONE;  // Drop the packet.
      } else {
        action->action = TCP_SEND_RAW_RST;
      }
      return;
    }
  }

  if (tcp_hdr->flags & TCP_FLAG_RST) {
    if (!(tcp_hdr->flags & TCP_FLAG_ACK)) {
      KLOG(DEBUG, "TCP: socket %p ignoring RST without an ACK\n", socket);
    } else {
      KLOG(DEBUG, "TCP: socket %p received RST\n", socket);
      socket->error = ECONNREFUSED;
      finish_protocol_close(socket, "connection refused");
    }
    action->action = TCP_ACTION_NONE;
    return;
  }

  if (tcp_hdr->flags & TCP_FLAG_SYN) {
    socket->recv_next = btoh32(tcp_hdr->seq) + 1;
    socket->send_wndsize = btoh16(tcp_hdr->wndsize);
    socket->send_buf_seq = socket->send_next;

    if (tcp_hdr->flags & TCP_FLAG_ACK) {
      set_state(socket, TCP_ESTABLISHED, "SYN-ACK received");
      action->send_ack = true;
      socket->send_unack = btoh32(tcp_hdr->ack);
      KASSERT_DBG(socket->send_unack == socket->send_next);
      socket->syn_acked = true;

      tcp_segment_t* seg =
          container_of(socket->segments.head, tcp_segment_t, link);
      KASSERT_DBG(seg->flags == TCP_FLAG_SYN);
      KASSERT_DBG(seg->data_len == 0);
      KASSERT_DBG(seg->seq == socket->initial_seq);
      tcp_cancel_timer(socket);
      segment_acked(socket, seg, 1);
      list_pop(&socket->segments);
      kfree(seg);
    } else {
      set_state(socket, TCP_SYN_RCVD, "SYN received (simultaneous open)");
      KASSERT_DBG(socket->send_unack == socket->send_next - 1);
      KASSERT_DBG(!list_empty(&socket->segments));
      // Update the already-sent segment and retransmit it.  As a side effect,
      // we won't measure the first RTT (since we consider it technically a
      // retransmit) --- meh.
      tcp_segment_t* seg =
          container_of(socket->segments.head, tcp_segment_t, link);
      KASSERT_DBG(seg->flags == TCP_FLAG_SYN);
      seg->flags |= TCP_FLAG_ACK;
      action->action = TCP_RETRANSMIT;
    }
  } else {
    KLOG(DEBUG, "TCP: socket %p dropping packet without SYN or RST\n", socket);
    action->action = TCP_ACTION_NONE;
  }
}

static void tcp_handle_in_listen(socket_tcp_t* parent, const pbuf_t* pb,
                                 const tcp_packet_metadata_t* md) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(kspin_is_held(&parent->spin_mu));

  if (tcp_hdr->flags & TCP_FLAG_RST) {
    KLOG(DEBUG, "TCP: socket %p ignoring RST in LISTEN\n", parent);
    kspin_unlock(&parent->spin_mu);
    return;
  }

  bool reset = false;
  if (tcp_hdr->flags != TCP_FLAG_SYN || md->data_len > 0) {
    KLOG(DEBUG, "TCP: socket %p RST for non-SYN in LISTEN\n", parent);
    reset = true;
  }

  KASSERT_DBG(parent->queued >= 0 && parent->queued <= parent->max_accept);
  if (parent->queued >= parent->max_accept) {
    KLOG(DEBUG, "TCP: socket %p rejecting connection (max queued)\n", parent);
    reset = true;
  }

  if (reset) {
    kspin_unlock(&parent->spin_mu);

    int result = tcp_send_raw_rst(pb, md);
    if (result != 0) {
      KLOG(WARNING, "TCP: socket %p unable to send RST: %s\n", parent,
           errorname(-result));
    }
    return;
  }

  socket_t* child_base = NULL;
  int result = sock_tcp_create(parent->base.s_domain, SOCK_STREAM, IPPROTO_TCP,
                               &child_base);
  if (result) {
    KLOG(INFO, "TCP: socket %p unable to spawn child connection: %s\n", parent,
         errorname(-result));
    kspin_unlock(&parent->spin_mu);
    return;
  }

  socket_tcp_t* child = (socket_tcp_t*)child_base;
  // It's safe to lock the child's mutex (even though we have the parent mutex
  // held) because no one else can access it yet.  Not strictly necessary.
  kspin_lock(&child->spin_mu);
  if (parent->iss_set) {
    set_iss(child, parent->initial_seq);
    child->iss_set = true;
  }
  child->rto_ms = parent->rto_ms;  // For tests.
  child->rto_min_ms = parent->rto_min_ms;
  child->parent = parent;
  refcount_inc(&parent->ref);
  list_push(&parent->children_connecting, &child->link);
  parent->queued++;

  child->bind_addr = md->dst;
  child->connected_addr = md->src;
  child->recv_next = btoh32(tcp_hdr->seq) + 1;
  child->send_wndsize = btoh16(tcp_hdr->wndsize);  // Note: won't be used...
  child->send_buf_seq = child->send_next + 1;
  set_state(child, TCP_SYN_RCVD, "new incoming connection");

  // Add the new socket to the connected sockets table.
  kspin_lock(&g_tcp.lock);
  result = tcpsm_bind(&g_tcp.sockets, &child->bind_addr, &child->connected_addr,
                      child->tcp_flags, child);
  if (result) {
    // This could happen (with SMP) if we race with another incoming connection.
    KLOG(DEBUG, "TCP: socket %p unable to accept incoming connection: %s\n",
         parent, errorname(-result));
    kspin_unlock(&g_tcp.lock);

    child->parent = NULL;
    list_remove(&parent->children_connecting, &child->link);
    parent->queued--;
    KASSERT(refcount_dec(&parent->ref) > 0);
    set_state(child, TCP_CLOSED_DONE, "unable to accept connection");
    kspin_unlock(&child->spin_mu);
    TCP_DEC_REFCOUNT(child);
    kspin_unlock(&parent->spin_mu);
    return;
  }
  refcount_inc(&child->ref);
  kspin_unlock(&g_tcp.lock);

  KASSERT_DBG(get_sockaddrs_port(&child->bind_addr) ==
              get_sockaddrs_port(&md->dst));

  // Send SYN-ACK.
  kspin_unlock(&child->spin_mu);
  kspin_unlock(&parent->spin_mu);

  result = tcp_send_syn(child, /* ack */ true, /* allow_block */ false);
  if (result != 0) {
    KLOG(WARNING, "TCP: socket %p unable to send SYN-ACK: %s\n", child,
         errorname(-result));
  }
}

static void maybe_handle_time_wait_fin(socket_tcp_t* socket, const pbuf_t* pb,
                                       const tcp_packet_metadata_t* md,
                                       uint32_t seq) {
  const tcp_hdr_t* tcp_hdr = (const tcp_hdr_t*)pbuf_getc(pb);
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  KASSERT_DBG(socket->state == TCP_TIME_WAIT);

  if (!(tcp_hdr->flags & TCP_FLAG_FIN) ||
      (seq + (uint32_t)md->data_len) != socket->recv_next - 1) {
    KLOG(DEBUG3, "TCP: socket %p ignoring non-retransmitted-FIN in TIME_WAIT\n",
         socket);
    return;
  }

  // This is a retransmit of the FIN.  Reset our TIME_WAIT timer.
  KLOG(DEBUG2,
       "TCP: socket %p got retransmitted FIN; resetting TIME_WAIT timer\n",
       socket);
  tcp_set_timer(socket, socket->time_wait_ms, /* force */ true);
}

// Closes the socket on the protocol side when all protocol ops are complete.
// Could be called from a user context or a defint.
static void finish_protocol_close(socket_tcp_t* socket, const char* reason) {
  KASSERT(kspin_is_held(&socket->spin_mu));
  // TODO(tcp): assert that we're coming from a last-to-terminal state, OR that
  // an error has occurred.

  // Cancel any pending timers.  A timer may be about to run (if it holds a
  // reference) once we unlock --- it will find the socket closed.
  tcp_cancel_timer(socket);

  KASSERT(socket->state != TCP_CLOSED_DONE);

  // If bound, remove from the socket table.
  if (socket->bind_addr.sa_family != AF_UNSPEC) {
    KASSERT_DBG(socket->bind_addr.sa_family ==
                (sa_family_t)socket->base.s_domain);
    const struct sockaddr_storage* remote = &socket->connected_addr;
    if (remote->sa_family == AF_UNSPEC) {
      KASSERT(socket->state == TCP_CLOSED || socket->state == TCP_LISTEN);
      remote = NULL;
    } else {
      KASSERT(socket->state != TCP_CLOSED);
      KASSERT(remote->sa_family == (sa_family_t)socket->base.s_domain);
    }
    kspin_lock(&g_tcp.lock);
    int result =
        tcpsm_remove(&g_tcp.sockets, &socket->bind_addr, remote, socket);
    kspin_unlock(&g_tcp.lock);
    if (result) {
      char buf1[SOCKADDR_PRETTY_LEN], buf2[SOCKADDR_PRETTY_LEN];
      KLOG(DFATAL,
           "TCP: socket %p connected (bound to %s, connected to %s) but not in "
           "sockets table\n",
           socket,
           sockaddr2str((struct sockaddr*)&socket->bind_addr,
                        sizeof(struct sockaddr_storage), buf1),
           sockaddr2str((struct sockaddr*)&socket->connected_addr,
                        sizeof(struct sockaddr_storage), buf2));
    }
    clear_addr(&socket->bind_addr);
    clear_addr(&socket->connected_addr);
    KASSERT(refcount_dec(&socket->ref) > 0);
  }

  while (!list_empty(&socket->segments)) {
    tcp_segment_t* seg =
        container_of(socket->segments.head, tcp_segment_t, link);
    uint32_t seg_len = tcp_seg_len(seg);
    KLOG(DEBUG3, "TCP: socket %p deleted unacked segment [%u, %u)\n", socket,
         seg->seq - socket->initial_seq,
         seg->seq + seg_len - socket->initial_seq);
    list_pop(&socket->segments);
    kfree(seg);
  }

  KASSERT_DBG(socket->bind_addr.sa_family == AF_UNSPEC);
  KASSERT_DBG(socket->connected_addr.sa_family == AF_UNSPEC);
  set_state(socket, TCP_CLOSED_DONE, reason);
}

static void reset_connection(socket_tcp_t* socket, const char* reason) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  if (socket->state == TCP_CLOSED_DONE) {
    KLOG(DEBUG3,
         "TCP: socket %p ignoring reset_connection() because socket already "
         "closed\n",
         socket);
    KASSERT_DBG(socket->recv_buf.len == 0);
    KASSERT_DBG(socket->send_buf.len == 0);
    return;
  }
  if (socket->state == TCP_SYN_RCVD && socket->parent) {
    // Keep the parent alive even while we (possibly) unlink ourselves from it.
    socket_tcp_t* parent = socket->parent;
    refcount_inc(&parent->ref);

    kspin_lock(&parent->spin_mu);
    // Can only update the lists if the parent is in LISTEN.  If not, the parent
    // is responsible for cleaning everything up --- at that point, we don't
    // care about our backlog queue anyway.
    if (parent->state == TCP_LISTEN) {
      list_remove(&parent->children_connecting, &socket->link);
      parent->queued--;
      KASSERT(refcount_dec(&socket->ref) > 0);
      KASSERT(refcount_dec(&parent->ref) > 0);
      socket->parent = NULL;
    } else {
      KASSERT_DBG(socket->parent->state == TCP_CLOSED_DONE);
    }
    kspin_unlock(&parent->spin_mu);
    KASSERT(refcount_dec(&parent->ref) > 0);
  }
  circbuf_clear(&socket->recv_buf);
  circbuf_clear(&socket->send_buf);
  socket->send_unack = socket->send_next;
  finish_protocol_close(socket, reason);
}

static void close_listening(socket_tcp_t* socket) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  finish_protocol_close(socket, "FD closed");

  KASSERT_DBG(socket->bind_addr.sa_family == AF_UNSPEC);
  KASSERT_DBG(socket->connected_addr.sa_family == AF_UNSPEC);

  // Copy the two lists locally and clear the socket versions --- this is not
  // totally necessary, but means we aren't touching the parent socket without
  // its lock held at all.
  list_t lists[2];
  lists[0] = socket->children_connecting;
  lists[1] = socket->children_established;
  socket->children_connecting = LIST_INIT;
  socket->children_established = LIST_INIT;
  socket->queued = 0;

  // We must clean up the queued sockets without the parent's lock held.
  kspin_unlock(&socket->spin_mu);

  test_point_run("tcp:close_listening");

  for (int i = 0; i < 2; ++i) {
    while (!list_empty(&lists[i])) {
      list_link_t* child_link = list_pop(&lists[i]);
      socket_tcp_t* child = container_of(child_link, socket_tcp_t, link);
      tcp_send_rst(child);  // Might fail if the socket is not connected.

      kspin_lock(&child->spin_mu);
      KASSERT(child->parent == socket);
      child->parent = NULL;
      reset_connection(child, "parent closed before accept()");
      kspin_unlock(&child->spin_mu);

      TCP_DEC_REFCOUNT(child);
      KASSERT(refcount_dec(&socket->ref) > 0);
    }
  }

  kspin_lock(&socket->spin_mu);
}

static int sock_tcp_shutdown(socket_t* socket_base, int how);

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
    finish_protocol_close(socket, "FD closed");
  } else if (socket->state == TCP_LISTEN) {
    close_listening(socket);
  }
  kspin_unlock(&socket->spin_mu);

  int result = sock_tcp_shutdown(socket_base, SHUT_RDWR);
  if (result != 0 && result != -ENOTCONN) {
    KLOG(DFATAL, "TCP: socket %p unable to shutdown() on close(): %s\n",
         socket_base, errorname(-result));
  }
  TCP_DEC_REFCOUNT(socket);
}

static int sock_tcp_shutdown(socket_t* socket_base, int how) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  if (how != SHUT_WR && how != SHUT_RD && how != SHUT_RDWR) {
    return -EINVAL;
  }

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;
  kspin_lock(&sock->spin_mu);
  bool send_datafin = false;
  if (how == SHUT_RD || how == SHUT_RDWR) {
    if (sock->recv_shutdown ||
        tcp_state_type(sock->state) == TCPSTATE_POST_ESTABLISHED) {
      kspin_unlock(&sock->spin_mu);
      return -ENOTCONN;
    }

    sock->recv_shutdown = true;
    circbuf_clear(&sock->recv_buf);
    tcp_wake(sock);
  }

  if (how == SHUT_WR || how == SHUT_RDWR) {
    if (sock->send_shutdown ||
        tcp_state_type(sock->state) == TCPSTATE_POST_ESTABLISHED) {
      // TODO(tcp): check we have tests for hitting this in all states
      // (including pre-established).
      kspin_unlock(&sock->spin_mu);
      return -ENOTCONN;
    }

    if (sock->state == TCP_SYN_SENT) {
      finish_protocol_close(sock, "shutdown(SHUT_WR) in SYN_SENT");
      tcp_wake(sock);
      kspin_unlock(&sock->spin_mu);
      return 0;
    }

    sock->send_shutdown = true;
    tcp_wake(sock);
    send_datafin = true;
  }
  kspin_unlock(&sock->spin_mu);

  if (send_datafin) {
    test_point_run("tcp:shutdown_before_send");
    // Send the FIN if possible.
    int result = tcp_send_datafin(sock, true);
    if (result != 0 && result != -EAGAIN) {
      KLOG(WARNING, "TCP: socket %p unable to send data/FIN: %s\n",
           sock, errorname(-result));
    }
  }
  return 0;  // Consider this a success even if sending FIN failed.
}

// TODO(aoates): this is almost exactly the same as UDP's bind; refactor/share?
static int sock_tcp_bind_locked(socket_tcp_t* socket,
                                const struct sockaddr* address,
                                socklen_t address_len, bool allow_rebind) {
  kmutex_assert_is_held(&socket->mu);

  // Check if the socket is CLOSED.  It's safe to check and then unlock because
  // the only way to leave CLOSED is by taking them mutex (which we hold) --- an
  // interrupt context will never cause us to leave CLOSED.
  kspin_lock(&socket->spin_mu);
  socktcp_state_t state = socket->state;
  kspin_unlock(&socket->spin_mu);
  if (state != TCP_CLOSED) {
    return -EINVAL;
  }

  if (socket->bind_addr.sa_family != AF_UNSPEC &&
      (!inet_is_anyaddr((const struct sockaddr*)&socket->bind_addr) ||
       !allow_rebind)) {
    return -EINVAL;
  }

  netaddr_t naddr;
  int naddr_port;
  int result = sock2netaddr(address, address_len, &naddr, &naddr_port);
  if (result == -EAFNOSUPPORT) return result;
  else if (result) return -EADDRNOTAVAIL;

  result = inet_bindable(&naddr);
  if (result) return result;

  kspin_lock(&g_tcp.lock);

  // As a special case, we may allow rebinding to a "more specific" IP on an
  // implicit bind during connection.
  if (allow_rebind && socket->bind_addr.sa_family != AF_UNSPEC) {
    // Sanity check --- we should be rebinding from <any-addr>:$PORT to
    // <specific-addr>:$PORT.  We should not have previously been able to bind
    // to the any-port (i.e. either bind_addr should be AF_UNSPEC, or have a
    // specific port, possibly chosen automatically).
    KASSERT_DBG(get_sockaddrs_port(&socket->bind_addr) == naddr_port);
    KASSERT_DBG(naddr_port != 0);
    KASSERT_DBG(inet_is_anyaddr((struct sockaddr*)&socket->bind_addr));
    KASSERT(tcpsm_remove(&g_tcp.sockets, &socket->bind_addr, NULL, socket) ==
            0);
    KASSERT(refcount_dec(&socket->ref) > 0);
  }

  // TODO(aoates): check for permission to bind to low-numbered ports.

  kmemcpy(&socket->bind_addr, address, address_len);
  result = tcpsm_bind(&g_tcp.sockets, &socket->bind_addr, NULL,
                      socket->tcp_flags, socket);
  kspin_unlock(&g_tcp.lock);
  if (result) {
    clear_addr(&socket->bind_addr);
    return result;
  }

  refcount_inc(&socket->ref);

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

  if (backlog <= 0) {
    backlog = DEFAULT_LISTEN_BACKLOG;
  } else if (backlog > SOMAXCONN) {
    backlog = SOMAXCONN;
  }

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;
  kspin_lock(&sock->spin_mu);
  if (sock->state != TCP_CLOSED) {
    kspin_unlock(&sock->spin_mu);
    return -EINVAL;
  }

  if (sock->bind_addr.sa_family == AF_UNSPEC) {
    kspin_unlock(&sock->spin_mu);
    return -EDESTADDRREQ;
  }

  KASSERT_DBG(sock->queued == 0);
  sock->max_accept = backlog;
  set_state(sock, TCP_LISTEN, "listen()");

  kspin_unlock(&sock->spin_mu);
  return 0;
}

static int sock_tcp_accept(socket_t* socket_base, int fflags,
                           struct sockaddr* address, socklen_t* address_len,
                           socket_t** socket_out) {
  KASSERT(socket_base->s_type == SOCK_STREAM);
  KASSERT(socket_base->s_protocol == IPPROTO_TCP);

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;
  kspin_lock(&sock->spin_mu);
  if (sock->state != TCP_LISTEN) {
    kspin_unlock(&sock->spin_mu);
    return -EINVAL;
  }

  int result = 0;
  while (list_empty(&sock->children_established)) {
    if (fflags & VFS_O_NONBLOCK) {
      result = -EAGAIN;
      break;
    }

    int wait_result = scheduler_wait_on_splocked(&sock->q, -1, &sock->spin_mu);
    if (wait_result == SWAIT_TIMEOUT) {
      KLOG(DFATAL, "TCP: timeout hit in accept()\n");
      result = -ETIMEDOUT;
      break;
    } else if (wait_result == SWAIT_INTERRUPTED) {
      result = -EINTR;
      break;
    }
    KASSERT(wait_result == SWAIT_DONE);
  }

  if (result < 0) {
    kspin_unlock(&sock->spin_mu);
    return result;
  }

  list_link_t* child_link = list_pop(&sock->children_established);
  sock->queued--;
  KASSERT_DBG(sock->queued >= 0);
  kspin_unlock(&sock->spin_mu);

  socket_tcp_t* child = container_of(child_link, socket_tcp_t, link);

  kspin_lock(&child->spin_mu);
  if (address && address_len) {
    *address_len = min(*address_len, (socklen_t)sizeof(child->connected_addr));
    KASSERT_DBG(*address_len > 0);
    kmemcpy(address, &child->connected_addr, *address_len);
  }

  KASSERT_DBG(child->parent == sock);
  child->parent = NULL;
  kspin_unlock(&child->spin_mu);

  // Transfer the ref from the parent's list to the new FD.
  *socket_out = &child->base;
  KASSERT(refcount_dec(&sock->ref) > 0);
  return 0;
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
    switch (tcp_state_type(sock->state)) {
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
    if (sock->state == TCP_LISTEN) {
      result = -EOPNOTSUPP;
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

  // Update our state and put us in the connected sockets table.  State must be
  // updated before the table, or atomically together.
  kspin_lock(&sock->spin_mu);
  // Mutex locked, and TCP_CLOSED is a defint-stable STATE.
  KASSERT_DBG(sock->state == TCP_CLOSED);

  kspin_lock(&g_tcp.lock);
  // First remove our bound address from the socket map, and other sockets can
  // now bind to our IP/port if SO_REUSE* is set (when implemented).  In the
  // case of an implicit bind, we're removing the entry we just added, whatever.
  result = tcpsm_remove(&g_tcp.sockets, &sock->bind_addr, NULL, sock);
  KASSERT(result == 0);

  // Now attempt to rebind to the full 5-tuple.
  struct sockaddr_storage address_sas;
  kmemcpy(&address_sas, address, address_len);
  result = tcpsm_bind(&g_tcp.sockets, &sock->bind_addr, &address_sas,
                      sock->tcp_flags, sock);
  if (result) {
    KLOG(WARNING, "TCP: unable to connect socket: %s\n", errorname(-result));
    kspin_unlock(&g_tcp.lock);

    clear_addr(&sock->bind_addr);
    reset_connection(sock, "unable to connect()");
    kspin_unlock(&sock->spin_mu);
    kmutex_unlock(&sock->mu);
    KASSERT(refcount_dec(&sock->ref) > 0);
    return result;
  }

  set_state(sock, TCP_SYN_SENT, "sending connect SYN");
  kmemcpy(&sock->connected_addr, address, address_len);
  kspin_unlock(&g_tcp.lock);

  kspin_unlock(&sock->spin_mu);

  // Send the initial SYN.  Always allow blocking here --- we want to block for
  // ARP even if the socket is non-blocking.
  result = tcp_send_syn(sock, /* ack */ false, /* allow_block */ true);
  kmutex_unlock(&sock->mu);
  if (result) {
    return result;
  }

  if (fflags & VFS_O_NONBLOCK) {
    return -EINPROGRESS;
  }

  // Wait until the socket is established or closes (with an error, presumably).
  kspin_lock(&sock->spin_mu);
  apos_ms_t now = get_time_ms();
  apos_ms_t timeout_end = (sock->connect_timeout_ms < 0)
                              ? APOS_MS_MAX
                              : now + sock->connect_timeout_ms;
  while (now < timeout_end &&
         tcp_state_type(sock->state) == TCPSTATE_PRE_ESTABLISHED) {
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

  socket_tcp_t* sock = (socket_tcp_t*)socket_base;
  kspin_lock(&sock->spin_mu);
  int result = -EINVAL;
  if (sock->state == TCP_LISTEN) {
    result = sock->queued;
  }
  kspin_unlock(&sock->spin_mu);
  return result;
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
  } else if (socket->recv_shutdown) {
    return RECV_EOF;
  }

  switch (socket->state) {
    case TCP_CLOSE_WAIT:
    case TCP_CLOSED_DONE:
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
    case TCP_CLOSING:
      // No error, no data, and we've received a FIN --- return EOF.  Note that
      // we will return EOF after an error once the first call to recv() returns
      // the error --- this matches macos behavior, so seems fine.
      return RECV_EOF;

    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
      // No data available but we could get some; block.
      return RECV_BLOCK_FOR_DATA;

    case TCP_CLOSED:
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RCVD:
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
  while (now < timeout_end && recv_state(sock) == RECV_BLOCK_FOR_DATA) {
    if (fflags & VFS_O_NONBLOCK) {
      result = -EAGAIN;
      break;
    }

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

  bool send_ack = false;
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
        send_ack = maybe_update_recv_window(sock, /* force */ false);
        break;
    }
  }
  kspin_unlock(&sock->spin_mu);

  if (send_ack) {
    int result2 = tcp_send_ack(sock);
    if (result2) {
      KLOG(WARNING, "TCP: socket %p unable to send window update: %s\n", sock,
           errorname(-result2));
    }
  }

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
      return SEND_IS_SHUTDOWN;

    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_CLOSING:
    case TCP_TIME_WAIT:
      KLOG(DFATAL, "TCP: socket %p in state %s but send_shutdown is false\n",
           socket, state2str(socket->state));
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
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RCVD:
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
  while (now < timeout_end && send_state(sock) == SEND_BLOCK) {
    if (fflags & VFS_O_NONBLOCK) {
      result = -EAGAIN;
      break;
    }

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
    KASSERT_DBG(tcp_state_type(socket->state) != TCPSTATE_PRE_ESTABLISHED);
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
  if (tcp_state_type(socket->state) == TCPSTATE_PRE_ESTABLISHED) {
    result = -ENOTCONN;
  } else if (tcp_state_type(socket->state) == TCPSTATE_POST_ESTABLISHED) {
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

  socket_tcp_t* socket = (socket_tcp_t*)socket_base;
  kspin_lock(&socket->spin_mu);
  const short masked_events = tcp_poll_events(socket) & event_mask;
  kspin_unlock(&socket->spin_mu);
  if (masked_events || !poll)
    return masked_events;

  return poll_add_event(poll, &socket->poll_event, event_mask);
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
  maybe_update_recv_window(socket, /* force */ true);
  kspin_unlock(&socket->spin_mu);
  return 0;
}

static int tcp_getsockopt_int(socket_tcp_t* socket, const int* dst,
                              void* restrict val, socklen_t* restrict val_len) {
  kspin_lock(&socket->spin_mu);
  int dst_val = *dst;
  kspin_unlock(&socket->spin_mu);
  return getsockopt_int(val, val_len, dst_val);
}

static int tcp_setsockopt_posint(socket_tcp_t* socket, int* dst,
                                 const void* val, socklen_t val_len) {
  int parsed_val;
  int result = setsockopt_int(val, val_len, &parsed_val);
  if (result) {
    return result;
  }
  if (parsed_val <= 0) {
    return -EINVAL;
  }

  kspin_lock(&socket->spin_mu);
  *dst = parsed_val;
  kspin_unlock(&socket->spin_mu);
  return 0;
}

// For a sockopt that is passed as an int but stored in a uint32_t.
static int tcp_getsockopt_int_u32(socket_tcp_t* socket, const uint32_t* dst,
                                  void* restrict val,
                                  socklen_t* restrict val_len) {
  kspin_lock(&socket->spin_mu);
  int dst_val = (int)*dst;
  kspin_unlock(&socket->spin_mu);
  if (dst_val < 0) {
    return -ERANGE;
  }
  return getsockopt_int(val, val_len, dst_val);
}

static int tcp_setsockopt_int_u32(socket_tcp_t* socket, uint32_t* dst,
                                  const void* restrict val, socklen_t val_len) {
  int parsed_val;
  int result = setsockopt_int(val, val_len, &parsed_val);
  if (result) {
    return result;
  }
  if (parsed_val <= 0) {
    return -EINVAL;
  }

  kspin_lock(&socket->spin_mu);
  *dst = parsed_val;
  kspin_unlock(&socket->spin_mu);
  return 0;
}

static int tcp_getsockopt_flag(socket_tcp_t* socket, int flag,
                               void* restrict val,
                               socklen_t* restrict val_len) {
  kspin_lock(&socket->spin_mu);
  bool dst_val = socket->tcp_flags & flag;
  kspin_unlock(&socket->spin_mu);
  return getsockopt_int(val, val_len, dst_val);
}

static int tcp_setsockopt_flag(socket_tcp_t* socket, int flag,
                               const void* restrict val, socklen_t val_len) {
  int parsed_val;
  int result = setsockopt_int(val, val_len, &parsed_val);
  if (result) {
    return result;
  }
  kspin_lock(&socket->spin_mu);
  if (parsed_val) {
    socket->tcp_flags |= flag;
  } else {
    socket->tcp_flags &= ~flag;
  }
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
  } else if (level == SOL_SOCKET && option == SO_ERROR) {
    kspin_lock(&socket->spin_mu);
    int err = socket->error;
    socket->error = 0;
    kspin_unlock(&socket->spin_mu);
    return getsockopt_int(val, val_len, err);
  } else if (level == SOL_SOCKET && option == SO_REUSEADDR) {
    return tcp_getsockopt_flag(socket, TCPSM_REUSEADDR, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_SEQ_NUM) {
    kspin_lock(&socket->spin_mu);
    if (socket->state != TCP_CLOSED) {
      kspin_unlock(&socket->spin_mu);
      return -EISCONN;
    }

    int seq = (int)socket->initial_seq;
    kspin_unlock(&socket->spin_mu);
    return getsockopt_int(val, val_len, seq);
  } else if (level == IPPROTO_TCP && option == SO_TCP_SOCKSTATE) {
    kspin_lock(&socket->spin_mu);
    socktcp_state_t state = socket->state;
    kspin_unlock(&socket->spin_mu);
    return getsockopt_cstr(val, val_len, state2str(state));
  } else if (level == IPPROTO_TCP && option == SO_TCP_TIME_WAIT_LEN) {
    return tcp_getsockopt_int(socket, &socket->time_wait_ms, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_RTO) {
    return tcp_getsockopt_int(socket, &socket->rto_ms, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_RTO_MIN) {
    return tcp_getsockopt_int(socket, &socket->rto_min_ms, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_CWND) {
    return tcp_getsockopt_int_u32(socket, &socket->cwnd.cwnd, val, val_len);
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
  } else if (level == SOL_SOCKET && option == SO_REUSEADDR) {
    return tcp_setsockopt_flag(socket, TCPSM_REUSEADDR, val, val_len);
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
    set_iss(socket, (uint32_t)seq);
    socket->iss_set = true;
    kspin_unlock(&socket->spin_mu);
    return 0;
  } else if (level == IPPROTO_TCP && option == SO_TCP_SOCKSTATE) {
    return -EINVAL;
  } else if (level == IPPROTO_TCP && option == SO_TCP_TIME_WAIT_LEN) {
    return tcp_setsockopt_posint(socket, &socket->time_wait_ms, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_RTO) {
    return tcp_setsockopt_posint(socket, &socket->rto_ms, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_RTO_MIN) {
    return tcp_setsockopt_posint(socket, &socket->rto_min_ms, val, val_len);
  } else if (level == IPPROTO_TCP && option == SO_TCP_CWND) {
    return tcp_setsockopt_int_u32(socket, &socket->cwnd.cwnd, val, val_len);
  }

  return -ENOPROTOOPT;
}

static short tcp_poll_events(const socket_tcp_t* socket) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  short events = 0;
  if (socket->error) {
    events |= KPOLLERR;
  }

  if (socket->state == TCP_LISTEN) {
    if (!list_empty(&socket->children_established)) {
      events |= KPOLLIN | KPOLLRDNORM;
    }
  } else {
    switch (recv_state(socket)) {
      case RECV_NOT_CONNECTED:
      case RECV_BLOCK_FOR_DATA:
        break;

      case RECV_ERROR:
        KASSERT_DBG(events & KPOLLERR);
        break;

      case RECV_HAS_DATA:
      case RECV_EOF:
        events |= KPOLLIN | KPOLLRDNORM;
        break;
    }

    switch (send_state(socket)) {
      case SEND_NOT_CONNECTED:
      case SEND_BLOCK:
      case SEND_IS_SHUTDOWN:
        break;

      case SEND_ERROR:
        KASSERT_DBG(events & KPOLLERR);
        break;

      case SEND_HAS_BUFFER:
        events |= KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND;
        break;
    }
  }
  return events;
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
