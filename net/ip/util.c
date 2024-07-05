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

#include "net/ip/util.h"

#include "common/errno.h"
#include "dev/net/nic.h"
#include "net/ip/ip6_addr.h"
#include "net/ip/route.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "test/test_point.h"

int ip6_pick_nic_src(const netaddr_t* dst, nic_t* nic, netaddr_t* src_out) {
  int best = -1;
  kspin_lock(&nic->lock);
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].a.addr.family != AF_INET6 ||
        nic->addrs[i].state != NIC_ADDR_ENABLED) {
      continue;
    }
    if (best < 0 ||
        ip6_src_addr_cmp(&nic->addrs[i], &nic->addrs[best], dst, nic) > 0) {
      best = i;
    }
  }
  if (best < 0) {
    kspin_unlock(&nic->lock);
    return -EADDRNOTAVAIL;
  }
  *src_out = nic->addrs[best].a.addr;
  kspin_unlock(&nic->lock);
  return 0;
}

int ip_pick_src(const struct sockaddr* dst, socklen_t dst_len,
                struct sockaddr_storage* src_out) {
  netaddr_t ndst;
  int result = sock2netaddr(dst, dst_len, &ndst, NULL);
  if (result) return result;

  netaddr_t nsrc;
  result = ip_pick_src_netaddr(&ndst, &nsrc);
  if (result) {
    return result;
  }
  return net2sockaddr(&nsrc, 0, src_out, sizeof(struct sockaddr_storage));
}

int ip_pick_src_netaddr(const netaddr_t* ndst, netaddr_t* src_out) {
  ip_routed_t route;
  if (!ip_route(*ndst, &route)) {
    return -ENETUNREACH;
  }
  test_point_run("ip_pick_src:after_route");
  if (ndst->family == AF_INET6) {
    int result = ip6_pick_nic_src(ndst, route.nic, src_out);
    if (result) {
      nic_put(route.nic);
      return result;
    }
  } else {
    *src_out = route.src;
  }
  nic_put(route.nic);
  return 0;
}
