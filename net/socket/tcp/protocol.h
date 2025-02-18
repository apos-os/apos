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

#ifndef APOO_NET_SOCKET_TCP_PROTOCOL_H
#define APOO_NET_SOCKET_TCP_PROTOCOL_H

#include <stdint.h>

#include "common/list.h"
#include "dev/timer.h"
#include "net/addr.h"
#include "net/eth/ethertype.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/ip6_hdr.h"
#include "net/pbuf.h"
#include "net/socket/tcp/socket.h"

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint8_t _zeroes : 4, data_offset : 4;
#else
  uint8_t data_offset : 4, _zeroes : 4;
#endif
  uint8_t flags;
  uint16_t wndsize;
  uint16_t checksum;
  uint16_t urg_ptr;
} __attribute__((packed)) tcp_hdr_t;
_Static_assert(sizeof(tcp_hdr_t) == 20, "Bad tcp_hdr_t size");

#define TCP_FLAG_FIN 1
#define TCP_FLAG_SYN (1 << 1)
#define TCP_FLAG_RST (1 << 2)
#define TCP_FLAG_PSH (1 << 3)
#define TCP_FLAG_ACK (1 << 4)
#define TCP_FLAG_URG (1 << 5)
#define TCP_FLAG_ECE (1 << 6)
#define TCP_FLAG_CWR (1 << 7)

// Metadata for a transmitted TCP segment.  We store the data needed to
// reconstruct the segment from the socket's buffers, but not the exact flags
// and metadata sent on the wire.
typedef struct {
  uint32_t seq;   // Sequence number start.
  uint8_t flags;  // TCP flags on the packet (SYN/ACK/FIN).
  size_t data_len;    // Length of data on the packet (not including SYN/FIN).
  int retransmits;    // How many times this segment has been retransmitted.
  apos_ms_t tx_time;  // When the packet was transmitted.
  list_link_t link;
} tcp_segment_t;

// A generic IP pseudo-IP header (IPv4 or IPv6).
typedef struct {
  int domain;
  union {
    ip4_pseudo_hdr_t v4;
    ip6_pseudo_hdr_t v6;
  } hdr;
  size_t len;
} tcpip_pseudo_hdr_t;

// Calculate the checksum for a given packet, add the appropriate IP header, and
// send it.  The pbuf should be pointing at the TCP header.
int tcp_checksum_and_send(const socket_tcp_t* socket, pbuf_t* pb,
                          const tcpip_pseudo_hdr_t* pseudo_ip,
                          bool allow_block);

int tcp_send_ack(socket_tcp_t* socket);
int tcp_send_rst(socket_tcp_t* socket);

// Creates a SYN or SYN/ACK segment for the socket.
void tcp_syn_segment(const socket_tcp_t* socket, tcp_segment_t* seg_out,
                     bool ack) REQUIRES(socket->spin_mu);

// Calculates the next segment to send on the socket --- includes data and
// possibly a FIN.
void tcp_next_segment(const socket_tcp_t* socket, tcp_segment_t* seg_out)
    REQUIRES(socket->spin_mu);

// Build a packet from the segment spec, copying data from the socket's send
// buffer as needed.  Returns the length of the TCP header or -error.  Does not
// include the IP header or calculate the checksum.
//
// Requires the socket be spinlocked.
int tcp_build_segment(const socket_tcp_t* socket, const tcp_segment_t* seg,
                      pbuf_t** pb_out, tcpip_pseudo_hdr_t* pseudo_ip)
    REQUIRES(socket->spin_mu);

typedef struct {
  struct sockaddr_storage src;
  struct sockaddr_storage dst;
  size_t data_len;  // How many bytes of data.
  size_t ip_hdr_len;  // How many bytes were taken for the IP header.
  size_t data_offset;  // How far from the start the data starts.
} tcp_packet_metadata_t;

// Validate an incoming packet, pop the IP header, and extract information about
// the packet.  Returns true if valid (and parsed).
bool tcp_validate_packet(pbuf_t* pb, ethertype_t ethertype, ssize_t header_len,
                         tcp_packet_metadata_t* md);

// Returns the length of the TCP segment in octets, including SYN/FIN.
uint32_t tcp_packet_octets(const tcp_hdr_t* tcp_hdr,
                           const tcp_packet_metadata_t* md);
uint32_t tcp_seg_len(const tcp_segment_t* seg);

// Sends a RST in response to an incoming packet.
int tcp_send_raw_rst(const pbuf_t* pb, const tcp_packet_metadata_t* md);

#endif
