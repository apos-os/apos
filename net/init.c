// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#include "net/init.h"

#include "common/kassert.h"
#include "dev/net/loopback.h"
#include "dev/net/nic.h"
#include "net/ip/ip6.h"
#include "net/ip/ip6_multicast.h"
#include "net/ip/route.h"
#include "net/util.h"
#include "user/include/apos/net/socket/inet.h"

void net_init(void) {
  // Basic static configuration to get things going.  This should not be in the
  // kernel, and _definitely_ not be hard-coded.
  // TODO(aoates): do better than this.
  nic_t* lo = loopback_create();
  kspin_lock(&lo->lock);
  lo->addrs[0].state = NIC_ADDR_ENABLED;
  lo->addrs[0].a.addr.family = ADDR_INET;
  lo->addrs[0].a.addr.a.ip4.s_addr = str2inet("127.0.0.1");
  lo->addrs[0].a.prefix_len = 8;

  lo->addrs[1].state = NIC_ADDR_ENABLED;
  lo->addrs[1].a.addr.family = ADDR_INET6;
  KASSERT(0 == str2inet6("::1", &lo->addrs[1].a.addr.a.ip6));
  lo->addrs[1].a.prefix_len = 128;
  kspin_unlock(&lo->lock);

  nic_t* nic = nic_get_nm("eth0");
  if (nic) {
    kspin_lock(&nic->lock);
    nic->addrs[0].state = NIC_ADDR_ENABLED;
    nic->addrs[0].a.addr.family = ADDR_INET;
    nic->addrs[0].a.addr.a.ip4.s_addr = str2inet("10.0.2.8");
    nic->addrs[0].a.prefix_len = 24;
    kspin_unlock(&nic->lock);

    ipv6_enable(nic, ipv6_default_nic_opts());
  }

  netaddr_t def;
  def.family = AF_INET;
  def.a.ip4.s_addr = str2inet("10.0.2.2");
  ip_set_default_route(ADDR_INET, def, "eth0");

  // TODO(ipv6): remove this hard-coded default route when we can auto-learn via
  // SLAAC.
  def.family = AF_INET6;
  KASSERT(0 == str2inet6("fe80::2", &def.a.ip6));
  ip_set_default_route(ADDR_INET6, def, "eth0");
}
