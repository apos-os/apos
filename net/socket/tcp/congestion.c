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

#include "net/socket/tcp/congestion.h"

#include "common/kassert.h"
#include "common/math.h"

void tcp_cwnd_init(tcp_cwnd_t* cw, uint32_t mss) {;
  // Per RFC 5681.
  if (mss > 2190) {
    cw->cwnd = 2 * mss;
  } else if (mss > 1095) {
    cw->cwnd = 3 * mss;
  } else {
    cw->cwnd = 4 * mss;
  }
  cw->mss = mss;
  cw->ssthresh = INT32_MAX;
  cw->acked = 0;
  cw->fast_retransmit = false;
}

void tcp_cwnd_acked(tcp_cwnd_t* cw, ssize_t len) {
  KASSERT(len > 0);
  if (cw->fast_retransmit) {
    cw->fast_retransmit = false;
    cw->cwnd = cw->ssthresh;
  } else if (cw->cwnd <= cw->ssthresh) {
    // In slow-start.  Increase accordingly.
    cw->cwnd += min((uint32_t)len, cw->mss);
  } else {
    cw->acked += len;
    if ((uint32_t)cw->acked >= cw->cwnd) {
      cw->cwnd += cw->mss;
      cw->acked = 0;
    }
  }
}

void tcp_cwnd_rto(tcp_cwnd_t* cw, uint32_t bytes_outstanding) {
  cw->ssthresh = max(bytes_outstanding / 2, 2 * cw->mss);
  cw->cwnd = cw->mss;
}

void tcp_cwnd_dupack(tcp_cwnd_t* cw, uint32_t bytes_outstanding,
                     int ack_count) {
  cw->fast_retransmit = true;
  // Per RFC 5681.
  if (ack_count == 3) {
    cw->ssthresh = max(bytes_outstanding / 2, 2 * cw->mss);
    cw->cwnd = cw->ssthresh + 3 * cw->mss;
  } else if (ack_count > 3) {
    cw->cwnd += cw->mss;
  }
}
