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

#include "net/ip/ip4_hdr.h"
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

int tcp_send_syn(socket_tcp_t* socket, int fflags);
int tcp_send_ack(socket_tcp_t* socket);
int tcp_send_fin(socket_tcp_t* socket);
int tcp_send_rst(socket_tcp_t* socket);

// Creates (but does not send) a data+FIN packet.  Requires the socket be
// spinlocked.
int tcp_create_datafin(socket_tcp_t* socket, uint32_t seq_start, size_t datalen,
                       ip4_pseudo_hdr_t* pseudo_ip, pbuf_t** pb_out);

typedef struct {
  struct sockaddr_storage src;
  struct sockaddr_storage dst;
  size_t data_len;  // How many bytes of data.
  size_t ip_hdr_len;  // How many bytes were taken for the IP header.
  size_t data_offset;  // How far from the start the data starts.
} tcp_packet_metadata_t;

// Validate an incoming packet, pop the IP header, and extract information about
// the packet.  Returns true if valid (and parsed).
bool tcp_validate_packet(pbuf_t* pb, tcp_packet_metadata_t* md);

#endif
