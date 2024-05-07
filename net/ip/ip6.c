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
#include "net/ip/ip6.h"

#include "common/kassert.h"
#include "common/klog.h"
#include "net/addr.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

#define LINK_LOCAL_PREFIX "fe80::"

void ipv6_enable(nic_t* nic) {
  // Start by generating a link-local address for the interface.
  // TODO(ipv6): do this properly randomly.
  struct in6_addr link_local;
  KASSERT(0 == str2inet6(LINK_LOCAL_PREFIX, &link_local));
  link_local.s6_addr[15] = 1;

  kspin_lock(&nic->lock);
  int open = -1;
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].addr.family == ADDR_INET6) {
      KLOG(INFO, "ipv6: nic %s already has IPv6 address\n", nic->name);
      kspin_unlock(&nic->lock);
      return;
    } else if (open < 0 && nic->addrs[i].addr.family == ADDR_UNSPEC) {
      open = i;
    }
  }

  if (open < 0) {
    KLOG(INFO, "ipv6: can't configure ipv6 on nic %s; no addresses available\n",
         nic->name);
    kspin_unlock(&nic->lock);
    return;
  }

  nic->addrs[open].addr.a.ip6 = link_local;
  nic->addrs[open].addr.family = ADDR_INET6;
  nic->addrs[open].prefix_len = 64;
  kspin_unlock(&nic->lock);

  char buf[INET6_PRETTY_LEN];
  KLOG(INFO, "ipv6: configured nic %s with addr %s\n", nic->name,
       inet62str(&link_local, buf));
  // TODO(ipv6): subscribe to multicast groups
  // TODO(ipv6): kick off SLAAC.
}
