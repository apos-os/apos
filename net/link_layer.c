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

#include "net/link_layer.h"

#include "common/klog.h"
#include "net/eth/arp/arp.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

void net_link_recv(nic_t* nic, pbuf_t* pb, ethertype_t protocol) {
  switch (protocol) {
    case ET_IPV4:
      // TODO(aoates): handle IP packets.
      break;

    case ET_ARP:
      arp_rx(nic, pb);
      return;
  }

  KLOG(INFO, "rx(%s): dropping packet with unknown ethertype %#06x\n",
       nic->name, protocol);
  pbuf_free(pb);
}
