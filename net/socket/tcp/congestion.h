// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_SOCKET_TCP_CONGESTION_H
#define APOO_NET_SOCKET_TCP_CONGESTION_H

#include <stdbool.h>
#include <stdint.h>

#include "common/types.h"

// Congestion control state for a socket.
typedef struct {
  // Current congestion window size.
  uint32_t cwnd;

  // Internal state for the congestion algorithm.
  uint32_t mss;
  uint32_t ssthresh;

  // How many bytes have been acked since the last cwnd increase.
  ssize_t acked;

  // Whether we're in fast retransmit mode (duplicate ACKs).
  bool fast_retransmit;
} tcp_cwnd_t;

// Initialize the congestion state.
void tcp_cwnd_init(tcp_cwnd_t* cw, uint32_t mss);

// New data is ACK'd.
void tcp_cwnd_acked(tcp_cwnd_t* cw, ssize_t len);

// Loss is detected due to the retransmit timer firing, and data was
// retransmitted for the first time.
void tcp_cwnd_rto(tcp_cwnd_t* cw, uint32_t bytes_outstanding);

// A duplicate ACK has been received.  |ack_count| is the number of times the
// ACK has been received (i.e. ack_count will be 1 on the first duplicate ACK).
void tcp_cwnd_dupack(tcp_cwnd_t* cw, uint32_t bytes_outstanding, int ack_count);

#endif
