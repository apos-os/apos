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

#include "net/ip/ip.h"

#include "common/errno.h"
#include "common/klog.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/route.h"
#include "net/link_layer.h"
#include "net/util.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

int ip_send(pbuf_t* pb) {
  if (pbuf_size(pb) < sizeof(ip4_hdr_t)) {
    KLOG(INFO, "net: rejecting too-short IP packet\n");
    return -EINVAL;
  }

  ip4_hdr_t* hdr = (ip4_hdr_t*)pbuf_get(pb);
  if (hdr->version_ihl >> 4 != 4) {
    KLOG(INFO, "net: rejecting IP packet with bad version %d\n",
         hdr->version_ihl >> 4);
    return -EINVAL;
  }

  netaddr_t dst;
  dst.family = AF_INET;
  dst.a.ip4.s_addr = hdr->dst_addr;
  ip_routed_t route;
  if (ip_route(dst, &route) == false) {
    char addrbuf[INET_PRETTY_LEN];
    KLOG(INFO, "net: unable to route packet to %s\n",
         inet2str(hdr->dst_addr, addrbuf));
    return -EINVAL;  // TODO
  }

  return net_link_send(route.nic, route.nexthop, pb, ET_IPV4);
}
