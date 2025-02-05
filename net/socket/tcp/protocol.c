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
#include "net/socket/tcp/protocol.h"

#include <stdint.h>

#include "common/circbuf.h"
#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "net/ip/checksum.h"
#include "net/ip/ip.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/ip6.h"
#include "net/ip/ip6_hdr.h"
#include "net/pbuf.h"
#include "net/socket/tcp/coverage.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/socket.h"
#include "net/util.h"
#include "proc/kthread.h"
#include "proc/spinlock.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

static const ip4_hdr_t* pb_ip4_hdr(const pbuf_t* pb) {
  return (const ip4_hdr_t*)pbuf_getc(pb);
}

static int pb_ip4_hdr_len(const pbuf_t* pb) {
  const ip4_hdr_t* ip_hdr = pb_ip4_hdr(pb);
  return ip4_ihl(*ip_hdr) * sizeof(uint32_t);
}

static const tcp_hdr_t* pb_tcp_hdr(const pbuf_t* pb, ssize_t header_len) {
  return (const tcp_hdr_t*)(pbuf_getc(pb) + header_len);
}

int tcp_checksum_and_send(const socket_tcp_t* socket, pbuf_t* pb,
                          const tcpip_pseudo_hdr_t* pseudo_ip,
                          bool allow_block) {
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  tcp_hdr->checksum = ip_checksum2(&pseudo_ip->hdr, pseudo_ip->len,
                                   pbuf_get(pb), pbuf_size(pb));

  if (pseudo_ip->domain  == AF_INET) {
    const ip4_pseudo_hdr_t* pv4 = &pseudo_ip->hdr.v4;
    ip4_add_hdr(pb, pv4->src_addr, pv4->dst_addr, IPPROTO_TCP);
    return ip_send(pb, allow_block);
  } else {
    KASSERT_DBG(pseudo_ip->domain == AF_INET6);
    const ip6_pseudo_hdr_t* pv6 = &pseudo_ip->hdr.v6;
    ip6_add_hdr(pb, &pv6->src_addr, &pv6->dst_addr, IPPROTO_TCP,
                socket ? socket->flow_label : 0);
    return ip6_send(pb, allow_block);
  }
}

static int tcp_build_packet(const socket_tcp_t* socket, int tcp_flags,
                            uint32_t seq, size_t data_len, pbuf_t** pb_out,
                            tcpip_pseudo_hdr_t* pseudo_ip) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));

  // In some race conditions we can attempt to send a packet an a connection
  // that was JUST closed.  Catch that case.
  if (socket->state == TCP_CLOSED_DONE) {
    KLOG(DEBUG, "TCP: socket %p cannot send packet on non-connected socket\n",
         socket);
    return -ENOTCONN;
  }
  KASSERT(socket->state != TCP_CLOSED);

  pbuf_t* pb = pbuf_create(
      inet_header_reserve(socket->base.s_domain) + sizeof(tcp_hdr_t), data_len);
  if (!pb) {
    return -ENOMEM;
  }
  *pb_out = pb;

  // Build the TCP header (minus checksum).
  pbuf_push_header(pb, sizeof(tcp_hdr_t));
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  KASSERT_DBG(socket->bind_addr.sa_family == AF_INET ||
              socket->bind_addr.sa_family == AF_INET6);
  KASSERT_DBG(socket->bind_addr.sa_family == (addrfam_t)socket->base.s_domain);
  KASSERT_DBG(socket->connected_addr.sa_family ==
              (addrfam_t)socket->base.s_domain);

  tcp_hdr->src_port = htob16(get_sockaddrs_port(&socket->bind_addr));
  tcp_hdr->dst_port = htob16(get_sockaddrs_port(&socket->connected_addr));
  tcp_hdr->seq = htob32(seq);
  tcp_hdr->ack = (tcp_flags & TCP_FLAG_ACK) ? htob32(socket->recv_next) : 0;
  _Static_assert(sizeof(tcp_hdr_t) % sizeof(uint32_t) == 0, "bad tcp hdr");
  tcp_hdr->data_offset = sizeof(tcp_hdr_t) / sizeof(uint32_t);
  tcp_hdr->_zeroes = 0;
  tcp_hdr->flags = tcp_flags;
  tcp_hdr->wndsize = htob16(socket->recv_wndsize);
  tcp_hdr->checksum = 0;
  tcp_hdr->urg_ptr = 0;

  // Prepare the pseudo-IP-header for the checksum.
  if (socket->base.s_domain == AF_INET) {
    const struct sockaddr_in* src =
        (const struct sockaddr_in*)&socket->bind_addr;
    const struct sockaddr_in* dst =
        (const struct sockaddr_in*)&socket->connected_addr;
    ip4_pseudo_hdr_t* pseudo_ip4  = &pseudo_ip->hdr.v4;
    pseudo_ip4->src_addr = src->sin_addr.s_addr;
    pseudo_ip4->dst_addr = dst->sin_addr.s_addr;
    pseudo_ip4->protocol = IPPROTO_TCP;
    KASSERT_DBG(data_len < UINT16_MAX - sizeof(tcp_hdr_t));
    pseudo_ip4->length = btoh16(sizeof(tcp_hdr_t) + data_len);
    pseudo_ip4->zeroes = 0;
    pseudo_ip->domain = AF_INET;
    pseudo_ip->len = sizeof(ip4_pseudo_hdr_t);
  } else {
    KASSERT(socket->base.s_domain == AF_INET6);
    const struct sockaddr_in6* src =
        (const struct sockaddr_in6*)&socket->bind_addr;
    const struct sockaddr_in6* dst =
        (const struct sockaddr_in6*)&socket->connected_addr;
    ip6_pseudo_hdr_t* pseudo_ip6 = &pseudo_ip->hdr.v6;
    pseudo_ip6->src_addr = src->sin6_addr;
    pseudo_ip6->dst_addr = dst->sin6_addr;
    kmemset(&pseudo_ip6->_zeroes, 0, 3);
    pseudo_ip6->next_hdr = IPPROTO_TCP;
    KASSERT_DBG(data_len < UINT16_MAX - sizeof(tcp_hdr_t));
    pseudo_ip6->payload_len = btoh16(sizeof(tcp_hdr_t) + data_len);
    pseudo_ip->domain = AF_INET6;
    pseudo_ip->len = sizeof(ip6_pseudo_hdr_t);
  }

  return sizeof(tcp_hdr_t);
}

static int send_flags_only_packet(socket_tcp_t* socket, int tcp_flags,
                                  bool allow_block) {
  pbuf_t* pb = NULL;
  tcpip_pseudo_hdr_t pseudo_ip;

  // Build the TCP header (minus checksum).
  kspin_lock(&socket->spin_mu);
  tcp_coverage_log("send_flags_only_packet", socket);
  int result = tcp_build_packet(socket, tcp_flags, socket->send_next,
                                /* data_len */ 0, &pb, &pseudo_ip);
  if (result < 0) {
    kspin_unlock(&socket->spin_mu);
    return result;
  }

  KASSERT(!(tcp_flags & TCP_FLAG_SYN));
  KASSERT(!(tcp_flags & TCP_FLAG_FIN));
  kspin_unlock(&socket->spin_mu);

  return tcp_checksum_and_send(socket, pb, &pseudo_ip, allow_block);
}

int tcp_send_ack(socket_tcp_t* socket) {
  return send_flags_only_packet(socket, TCP_FLAG_ACK, /* allow_block */ false);
}

int tcp_send_rst(socket_tcp_t* socket) {
  return send_flags_only_packet(socket, TCP_FLAG_RST | TCP_FLAG_ACK,
                                /* allow_block */ false);
}

void tcp_syn_segment(const socket_tcp_t* socket, tcp_segment_t* seg_out,
                     bool ack) {
  seg_out->seq = socket->initial_seq;
  seg_out->data_len = 0;
  seg_out->flags = TCP_FLAG_SYN;
  if (ack) seg_out->flags |= TCP_FLAG_ACK;
  seg_out->tx_time = 0;
  seg_out->link = LIST_LINK_INIT;
}

void tcp_next_segment(const socket_tcp_t* socket, tcp_segment_t* seg_out) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));

  // Figure out how much data to send.
  uint32_t unacked_data = socket->send_next - socket->send_unack;
  if (tcp_is_fin_sent(socket->state) && unacked_data > 0) {
    unacked_data--;
  }
  if (!socket->syn_acked) {
    KASSERT_DBG(unacked_data == 1);
    unacked_data--;
  }
  KASSERT_DBG(socket->send_buf.len >= unacked_data);
  size_t data_to_send =
      min(socket->cwnd.cwnd,
          socket->send_wndsize - min(socket->send_wndsize, unacked_data));
  data_to_send = min(data_to_send, socket->send_buf.len - unacked_data);
  data_to_send = min(data_to_send, socket->mss);

  // Determine if we should also send a FIN.
  uint32_t seq_start = socket->send_next;
  bool send_fin = false;
  if (socket->send_shutdown) {
    uint32_t fin_seq = socket->send_buf_seq + socket->send_buf.len;
    // We use equality here so that we don't attempt to send a FIN when
    // seq_start is past the FIN sequence number (which happens when this is
    // called after a FIN has been sent).
    if (seq_start + (uint32_t)data_to_send == fin_seq &&
        socket->send_wndsize - data_to_send >= 1) {
      send_fin = true;
    }
  }

  seg_out->seq = seq_start;
  seg_out->data_len = data_to_send;
  seg_out->flags = TCP_FLAG_ACK;
  if (send_fin) seg_out->flags |= TCP_FLAG_FIN;
  seg_out->tx_time = 0;
  seg_out->link = LIST_LINK_INIT;
}

int tcp_build_segment(const socket_tcp_t* socket, const tcp_segment_t* seg,
                      pbuf_t** pb_out, tcpip_pseudo_hdr_t* pseudo_ip) {
  if (seg->data_len == 0 && !(seg->flags & TCP_FLAG_SYN) &&
      !(seg->flags & TCP_FLAG_FIN)) {
    return -EAGAIN;
  }

  // Build the TCP header (minus checksum).
  pbuf_t* pb = NULL;
  int result = tcp_build_packet(socket, seg->flags, seg->seq, seg->data_len,
                                &pb, pseudo_ip);
  if (result < 0) {
    return result;
  }

  if (seg->data_len > 0) {
    // Note: this doesn't handle SYN+data correctly.
    uint32_t send_buf_offset = seg->seq - socket->send_buf_seq;
    KASSERT_DBG(socket->send_buf.len >= send_buf_offset);
    KASSERT_DBG(seg->data_len <= socket->send_buf.len - send_buf_offset);
    size_t bytes_copied =
        circbuf_peek(&socket->send_buf, pbuf_get(pb) + sizeof(tcp_hdr_t),
                     send_buf_offset, seg->data_len);
    if (bytes_copied != seg->data_len) {
      KLOG(DFATAL, "TCP: unable to copy %zd bytes to packet (copied %zd)\n",
           seg->data_len, bytes_copied);
      pbuf_free(pb);
      return -ENOMEM;
    }
  }
  *pb_out = pb;
  return 0;
}

int tcp_send_raw_rst(const pbuf_t* pb_in, const tcp_packet_metadata_t* md) {
  const tcp_hdr_t* tcp_hdr_in = (const tcp_hdr_t*)pbuf_getc(pb_in);
  pbuf_t* pb = pbuf_create(
      inet_header_reserve(md->src.sa_family) + sizeof(tcp_hdr_t), 0);
  if (!pb) {
    return -ENOMEM;
  }

  // Build the TCP header (minus checksum).
  pbuf_push_header(pb, sizeof(tcp_hdr_t));
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  KASSERT_DBG(md->src.sa_family == AF_INET || md->src.sa_family == AF_INET6);
  KASSERT_DBG(md->dst.sa_family == AF_INET || md->dst.sa_family == AF_INET6);

  uint32_t rst_seq, rst_ack;
  uint32_t rst_flags = TCP_FLAG_RST;
  if (tcp_hdr_in->flags & TCP_FLAG_ACK) {
    rst_seq = tcp_hdr_in->ack;
    rst_ack = 0;
  } else {
    rst_seq = 0;
    rst_ack =
        htob32(btoh32(tcp_hdr_in->seq) + tcp_packet_octets(tcp_hdr_in, md));
    rst_flags |= TCP_FLAG_ACK;
  }

  tcp_hdr->src_port = htob16(get_sockaddrs_port(&md->dst));
  tcp_hdr->dst_port = htob16(get_sockaddrs_port(&md->src));
  tcp_hdr->seq = rst_seq;
  tcp_hdr->ack = rst_ack;
  _Static_assert(sizeof(tcp_hdr_t) % sizeof(uint32_t) == 0, "bad tcp hdr");
  tcp_hdr->data_offset = sizeof(tcp_hdr_t) / sizeof(uint32_t);
  tcp_hdr->_zeroes = 0;
  tcp_hdr->flags = rst_flags;
  tcp_hdr->wndsize = 8000;
  tcp_hdr->checksum = 0;
  tcp_hdr->urg_ptr = 0;

  // Prepare the pseudo-IP-header for the checksum.
  tcpip_pseudo_hdr_t pseudo_ip;
  if (md->src.sa_family == AF_INET) {
    ip4_pseudo_hdr_t* pseudo_ip4 = &pseudo_ip.hdr.v4;
    const struct sockaddr_in* src = (const struct sockaddr_in*)&md->dst;
    const struct sockaddr_in* dst = (const struct sockaddr_in*)&md->src;
    pseudo_ip4->src_addr = src->sin_addr.s_addr;
    pseudo_ip4->dst_addr = dst->sin_addr.s_addr;
    pseudo_ip4->zeroes = 0;
    pseudo_ip4->protocol = IPPROTO_TCP;
    pseudo_ip4->length = btoh16(sizeof(tcp_hdr_t));
    pseudo_ip.domain = AF_INET;
    pseudo_ip.len = sizeof(ip4_pseudo_hdr_t);
  } else {
    ip6_pseudo_hdr_t* pseudo_ip6 = &pseudo_ip.hdr.v6;
    const struct sockaddr_in6* src = (const struct sockaddr_in6*)&md->dst;
    const struct sockaddr_in6* dst = (const struct sockaddr_in6*)&md->src;
    pseudo_ip6->src_addr = src->sin6_addr;
    pseudo_ip6->dst_addr = dst->sin6_addr;
    kmemset(&pseudo_ip6->_zeroes, 0, 3);
    pseudo_ip6->next_hdr = IPPROTO_TCP;
    pseudo_ip6->payload_len = btoh16(sizeof(tcp_hdr_t));
    pseudo_ip.domain = AF_INET6;
    pseudo_ip.len = sizeof(ip6_pseudo_hdr_t);
  }

  return tcp_checksum_and_send(NULL, pb, &pseudo_ip, /* allow_block */ false);
}

static bool validate_packet_v4(pbuf_t* pb, ssize_t header_len,
                               tcp_packet_metadata_t* md) {
  KASSERT_DBG((ssize_t)pbuf_size(pb) >= header_len);
  KASSERT_DBG(header_len >= (ssize_t)sizeof(ip4_hdr_t));
  KASSERT_DBG((size_t)pb_ip4_hdr_len(pb) >= sizeof(ip4_hdr_t));
  if (pbuf_size(pb) < sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t)) {
    klogfm(KL_TCP, INFO, "TCP: dropping truncated TCP packet\n");
    return false;
  }
  const ip4_hdr_t* ip_hdr = pb_ip4_hdr(pb);

  // Check the size in the packet header as well.
  if (btoh16(ip_hdr->total_len) < pb_ip4_hdr_len(pb) + sizeof(tcp_hdr_t)) {
    klogfm(KL_TCP, INFO, "TCP: dropping truncated TCP packet (IP header)\n");
    return false;
  }

  const tcp_hdr_t* tcp_hdr = pb_tcp_hdr(pb, header_len);
  KASSERT_DBG(btoh16(ip_hdr->total_len) <= pbuf_size(pb));
  const size_t tcp_len = btoh16(ip_hdr->total_len) - pb_ip4_hdr_len(pb);
  const size_t tcp_hdr_len = tcp_hdr->data_offset * sizeof(uint32_t);

  if (tcp_hdr_len < sizeof(tcp_hdr_t) ||
      tcp_hdr_len > btoh16(ip_hdr->total_len) - (size_t)pb_ip4_hdr_len(pb)) {
    klogfm(KL_TCP, INFO, "TCP: dropping TCP packet with bad header len\n");
    return false;
  }

  // Validate the checksum.
  md->data_len = tcp_len - tcp_hdr_len;
  md->data_offset = tcp_hdr_len;
  ip4_pseudo_hdr_t pseudo_ip;
  pseudo_ip.src_addr = ip_hdr->src_addr;
  pseudo_ip.dst_addr = ip_hdr->dst_addr;
  pseudo_ip.zeroes = 0;
  pseudo_ip.protocol = IPPROTO_TCP;
  pseudo_ip.length = btoh16(tcp_len);

  uint16_t checksum =
      ip_checksum2(&pseudo_ip, sizeof(pseudo_ip),
                   /* really TCP header _and_ data */ tcp_hdr, tcp_len);
  if (checksum != 0) {
    klogfm(KL_NET, INFO,
           "TCP: dropping TCP packet with bad checksum (header checksum: "
           "0x%04x; calculated checksum: 0x%04x\n",
           tcp_hdr->checksum, checksum);
    return false;
  }

  struct sockaddr_in* src_sin = (struct sockaddr_in*)&md->src;
  struct sockaddr_in* dst_sin = (struct sockaddr_in*)&md->dst;
  src_sin->sin_family = AF_INET;
  src_sin->sin_addr.s_addr = ip_hdr->src_addr;
  src_sin->sin_port = tcp_hdr->src_port;
  dst_sin->sin_family = AF_INET;
  dst_sin->sin_addr.s_addr = ip_hdr->dst_addr;
  dst_sin->sin_port = tcp_hdr->dst_port;

  md->ip_hdr_len = pb_ip4_hdr_len(pb);
  pbuf_pop_header(pb, pb_ip4_hdr_len(pb));
  return true;
}

static bool validate_packet_v6(pbuf_t* pb, ssize_t header_len,
                               tcp_packet_metadata_t* md) {
  KASSERT_DBG((ssize_t)pbuf_size(pb) >= header_len);
  KASSERT_DBG(header_len >= (ssize_t)sizeof(ip6_hdr_t));
  if (pbuf_size(pb) < header_len + sizeof(tcp_hdr_t)) {
    klogfm(KL_TCP, INFO, "TCP: dropping truncated TCP packet\n");
    return false;
  }
  const ip6_hdr_t* ip_hdr = (const ip6_hdr_t*)pbuf_getc(pb);

  // Check the size in the packet header as well.  There might be extra headers.
  KASSERT_DBG(btoh16(ip_hdr->payload_len) >= pbuf_size(pb) - header_len);

  const tcp_hdr_t* tcp_hdr = pb_tcp_hdr(pb, header_len);
  KASSERT_DBG(btoh16(ip_hdr->payload_len) <= pbuf_size(pb));
  const size_t tcp_len = pbuf_size(pb) - header_len;
  const size_t tcp_hdr_len = tcp_hdr->data_offset * sizeof(uint32_t);

  if (tcp_hdr_len < sizeof(tcp_hdr_t) ||
      tcp_hdr_len > pbuf_size(pb) - header_len) {
    klogfm(KL_TCP, INFO, "TCP: dropping TCP packet with bad header len\n");
    return false;
  }

  // Validate the checksum.
  md->data_len = tcp_len - tcp_hdr_len;
  md->data_offset = tcp_hdr_len;
  ip6_pseudo_hdr_t pseudo_ip;
  pseudo_ip.src_addr = ip_hdr->src_addr;
  pseudo_ip.dst_addr = ip_hdr->dst_addr;
  kmemset(&pseudo_ip._zeroes, 0, 3);
  pseudo_ip.next_hdr = IPPROTO_TCP;
  pseudo_ip.payload_len = btoh16(tcp_len);

  uint16_t checksum =
      ip_checksum2(&pseudo_ip, sizeof(pseudo_ip),
                   /* really TCP header _and_ data */ tcp_hdr, tcp_len);
  if (checksum != 0) {
    klogfm(KL_NET, INFO,
           "TCP: dropping TCP packet with bad checksum (header checksum: "
           "0x%04x; calculated checksum: 0x%04x\n",
           tcp_hdr->checksum, checksum);
    return false;
  }

  struct sockaddr_in6* src_sin = (struct sockaddr_in6*)&md->src;
  struct sockaddr_in6* dst_sin = (struct sockaddr_in6*)&md->dst;
  src_sin->sin6_family = AF_INET6;
  src_sin->sin6_addr = ip_hdr->src_addr;
  src_sin->sin6_port = tcp_hdr->src_port;
  src_sin->sin6_flowinfo = 0;
  src_sin->sin6_scope_id = 0;
  dst_sin->sin6_family = AF_INET6;
  dst_sin->sin6_addr = ip_hdr->dst_addr;
  dst_sin->sin6_port = tcp_hdr->dst_port;
  dst_sin->sin6_flowinfo = 0;
  dst_sin->sin6_scope_id = 0;

  md->ip_hdr_len = header_len;
  pbuf_pop_header(pb, header_len);
  return true;
}

bool tcp_validate_packet(pbuf_t* pb, ethertype_t ethertype, ssize_t header_len,
                         tcp_packet_metadata_t* md) {
  KASSERT_DBG((ssize_t)pbuf_size(pb) >= header_len);
  if (ethertype == ET_IPV4) {
    return validate_packet_v4(pb, header_len, md);
  } else if (ethertype == ET_IPV6) {
    return validate_packet_v6(pb, header_len, md);
  }
  return false;
}

uint32_t tcp_packet_octets(const tcp_hdr_t* tcp_hdr,
                           const tcp_packet_metadata_t* md) {
  size_t len = md->data_len;
  if (tcp_hdr->flags & TCP_FLAG_SYN) len++;
  if (tcp_hdr->flags & TCP_FLAG_FIN) len++;
  return len;
}

uint32_t tcp_seg_len(const tcp_segment_t* seg) {
  size_t len = seg->data_len;
  if (seg->flags & TCP_FLAG_SYN) len++;
  if (seg->flags & TCP_FLAG_FIN) len++;
  return len;
}
