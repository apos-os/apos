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
#include "common/kassert.h"
#include "common/math.h"
#include "net/ip/checksum.h"
#include "net/ip/ip.h"
#include "net/ip/ip4_hdr.h"
#include "net/pbuf.h"
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

static const tcp_hdr_t* pb_tcp_hdr(const pbuf_t* pb) {
  const size_t ip_hdr_len = pb_ip4_hdr_len(pb);
  return (const tcp_hdr_t*)(pbuf_getc(pb) + ip_hdr_len);
}

// Build a basic packet with the given data length.  Returns the length of the
// TCP header or -error.
static int tcp_build_packet(socket_tcp_t* socket, int tcp_flags,
                            size_t data_len, pbuf_t** pb_out,
                            ip4_pseudo_hdr_t* pseudo_ip) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  pbuf_t* pb = pbuf_create(INET_HEADER_RESERVE + sizeof(tcp_hdr_t), data_len);
  if (!pb) {
    return -ENOMEM;
  }
  *pb_out = pb;

  // Build the TCP header (minus checksum).
  pbuf_push_header(pb, sizeof(tcp_hdr_t));
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  KASSERT_DBG(socket->bind_addr.sa_family == AF_INET);
  KASSERT_DBG(socket->connected_addr.sa_family == AF_INET);

  const struct sockaddr_in* src = (const struct sockaddr_in*)&socket->bind_addr;
  const struct sockaddr_in* dst =
      (const struct sockaddr_in*)&socket->connected_addr;
  tcp_hdr->src_port = src->sin_port;
  tcp_hdr->dst_port = dst->sin_port;
  tcp_hdr->seq = htob32(socket->send_next);
  tcp_hdr->ack = (tcp_flags & TCP_FLAG_ACK) ? htob32(socket->recv_next) : 0;
  _Static_assert(sizeof(tcp_hdr_t) % sizeof(uint32_t) == 0, "bad tcp hdr");
  tcp_hdr->data_offset = sizeof(tcp_hdr_t) / sizeof(uint32_t);
  tcp_hdr->_zeroes = 0;
  tcp_hdr->flags = tcp_flags;
  tcp_hdr->wndsize = htob16(socket->recv_wndsize);
  tcp_hdr->checksum = 0;
  tcp_hdr->urg_ptr = 0;

  // Prepare the pseudo-IP-header for the checksum.
  pseudo_ip->src_addr = src->sin_addr.s_addr;
  pseudo_ip->dst_addr = dst->sin_addr.s_addr;
  pseudo_ip->zeroes = 0;
  pseudo_ip->protocol = IPPROTO_TCP;
  KASSERT_DBG(data_len < UINT16_MAX - sizeof(tcp_hdr_t));
  pseudo_ip->length = btoh16(sizeof(tcp_hdr_t) + data_len);

  return sizeof(tcp_hdr_t);
}

static int send_flags_only_packet(socket_tcp_t* socket, int tcp_flags,
                                  bool allow_block) {
  pbuf_t* pb = NULL;
  ip4_pseudo_hdr_t pseudo_ip;

  // Build the TCP header (minus checksum).
  kspin_lock(&socket->spin_mu);
  int result =
      tcp_build_packet(socket, tcp_flags, /* data_len */ 0, &pb, &pseudo_ip);
  if (result < 0) {
    kspin_unlock(&socket->spin_mu);
    return result;
  }

  if (tcp_flags & TCP_FLAG_SYN) socket->send_next++;
  if (tcp_flags & TCP_FLAG_FIN) socket->send_next++;
  kspin_unlock(&socket->spin_mu);

  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  tcp_hdr->checksum =
      ip_checksum2(&pseudo_ip, sizeof(pseudo_ip), pbuf_get(pb), pbuf_size(pb));

  ip4_add_hdr(pb, pseudo_ip.src_addr, pseudo_ip.dst_addr, IPPROTO_TCP);
  return ip_send(pb, allow_block);
}

int tcp_send_syn(socket_tcp_t* socket, int fflags) {
  kmutex_assert_is_held(&socket->mu);
  return send_flags_only_packet(socket, TCP_FLAG_SYN, /* allow_block */ true);
}

int tcp_send_ack(socket_tcp_t* socket) {
  return send_flags_only_packet(socket, TCP_FLAG_ACK, /* allow_block */ false);
}

int tcp_send_fin(socket_tcp_t* socket) {
  kmutex_assert_is_held(&socket->mu);
  return send_flags_only_packet(socket, TCP_FLAG_FIN | TCP_FLAG_ACK,
                                /* allow_block */ true);
}

int tcp_create_datafin(socket_tcp_t* socket, uint32_t seq_start,
                       size_t data_to_send, ip4_pseudo_hdr_t* pseudo_ip,
                       pbuf_t** pb_out) {
  KASSERT(kspin_is_held(&socket->spin_mu));
  bool send_fin = false;
  if (socket->send_shutdown) {
    uint32_t fin_seq = socket->send_buf_seq + socket->send_buf.len;
    if (seq_ge(seq_start + data_to_send, fin_seq)) {
      send_fin = true;
    }
  }
  uint32_t send_buf_offset = seq_start - socket->send_buf_seq;
  KASSERT_DBG(socket->send_buf.len >= send_buf_offset);
  if (data_to_send == 0 && !send_fin) {
    return -EAGAIN;
  }

  // Build the TCP header (minus checksum).
  pbuf_t* pb = NULL;
  uint32_t flags = TCP_FLAG_ACK;
  if (send_fin) flags |= TCP_FLAG_FIN;
  int result = tcp_build_packet(socket, flags, data_to_send, &pb, pseudo_ip);
  if (result < 0) {
    return result;
  }

  size_t bytes_copied =
      circbuf_peek(&socket->send_buf, pbuf_get(pb) + sizeof(tcp_hdr_t),
                   send_buf_offset, data_to_send);
  if (bytes_copied != data_to_send) {
    KLOG(DFATAL, "TCP: unable to copy %zd bytes to packet (copied %zd)\n",
         data_to_send, bytes_copied);
    pbuf_free(pb);
    return -ENOMEM;
  }
  *pb_out = pb;
  return 0;
}

bool tcp_validate_packet(pbuf_t* pb, tcp_packet_metadata_t* md) {
  KASSERT_DBG(pbuf_size(pb) >= sizeof(ip4_hdr_t));
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

  const tcp_hdr_t* tcp_hdr = pb_tcp_hdr(pb);
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
