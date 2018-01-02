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

#include "net/ip/route.h"

#include "arch/common/endian.h"
#include "common/kassert.h"
#include "dev/net/nic.h"

typedef struct {
  // TODO(aoates): support network matching.

  // The next hop to route to.
  // TODO(aoates): support this being the link address configured on a NIC.
  netaddr_t nexthop;

  // The device to use.
  // TODO(aoates): make this optional (so we can use nexthop alone).
  const char* nic_name;
} ip_route_rule_t;

// TODO(aoates): support multiple default routes (e.g. ipv4 and ipv6).
static ip_route_rule_t g_default_route;

static in_addr_t kNetMasks[33] = {
  0x00000000,
  0x80000000,
  0xc0000000,
  0xe0000000,
  0xf0000000,
  0xf8000000,
  0xfc000000,
  0xfe000000,
  0xff000000,
  0xff800000,
  0xffc00000,
  0xffe00000,
  0xfff00000,
  0xfff80000,
  0xfffc0000,
  0xfffe0000,
  0xffff0000,
  0xffff8000,
  0xffffc000,
  0xffffe000,
  0xfffff000,
  0xfffff800,
  0xfffffc00,
  0xfffffe00,
  0xffffff00,
  0xffffff80,
  0xffffffc0,
  0xffffffe0,
  0xfffffff0,
  0xfffffff8,
  0xfffffffc,
  0xfffffffe,
  0xffffffff,
};

static bool netmatch(const netaddr_t* addr, const network_t* network) {
  if (addr->family != network->addr.family) {
    return false;
  }
  switch (addr->family) {
    case ADDR_INET: {
      KASSERT_DBG(network->prefix_len <= 32 && network->prefix_len >= 0);
      const in_addr_t mask = htob32(kNetMasks[network->prefix_len]);
      return (addr->a.ip4.s_addr & mask) == (network->addr.a.ip4.s_addr & mask);
    }
  }

  // Unknown address type.
  return false;
}

// TODO(aoates): write some tests for this.
bool ip_route(netaddr_t dst, ip_routed_t* result) {
  // First try to find a NIC with a matching network.
  // N.B.(aoates): this isn't totally proper routing logic, but good enough for
  // now.
  int longest_prefix = 0;
  for (int nicidx = 0; nicidx < nic_count(); ++nicidx) {
    nic_t* nic = nic_get(nicidx);
    for (int addridx = 0; addridx < NIC_MAX_ADDRS &&
                              nic->addrs[addridx].addr.family != AF_UNSPEC;
         addridx++) {
      if (nic->addrs[addridx].prefix_len > longest_prefix &&
          netmatch(&dst, &nic->addrs[addridx])) {
        result->nic = nic;
        longest_prefix = nic->addrs[addridx].prefix_len;
      }
    }
  }
  if (longest_prefix > 0) {
    result->nexthop = dst;
    return true;
  }

  // No match, use the default route if we can.
  if (g_default_route.nexthop.family == dst.family) {
    result->nexthop = g_default_route.nexthop;
    result->nic = nic_get_nm(g_default_route.nic_name);
    return (result->nic != NULL);
  }

  // No match at all, can't route :(
  return false;
}

void ip_set_default_route(netaddr_t nexthop, const char* nic_name) {
  g_default_route.nexthop = nexthop;
  g_default_route.nic_name = nic_name;
}
