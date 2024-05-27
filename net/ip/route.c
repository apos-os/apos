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

#include "common/endian.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/refcount.h"
#include "dev/net/nic.h"
#include "net/addr.h"

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

bool ip_route(netaddr_t dst, ip_routed_t* result) {
  // First try to find a NIC with a matching network.
  // N.B.(aoates): this isn't totally proper routing logic, but good enough for
  // now.
  int longest_prefix = 0;
  nic_t* nic = nic_first();
  result->nic = NULL;
  while (nic) {
    kspin_lock(&nic->lock);
    // TODO(aoates): if we're going to assume a left-justified address list,
    // should track that explicitly.
    for (int addridx = 0; addridx < NIC_MAX_ADDRS &&
                          nic->addrs[addridx].state == NIC_ADDR_ENABLED;
         addridx++) {
      if (netaddr_eq(&nic->addrs[addridx].a.addr, &dst)) {
        // Sending to the NIC's own address---reroute via the loopback.
        // TODO(aoates): don't hard-code the loopback device name here.
        result->nic = nic_get_nm("lo0");
        result->nexthop = dst;
        result->src = nic->addrs[addridx].a.addr;
        kspin_unlock(&nic->lock);
        nic_put(nic);
        return (result->nic != NULL);
      }
      if (nic->addrs[addridx].a.prefix_len > longest_prefix &&
          netaddr_match(&dst, &nic->addrs[addridx].a)) {
        if (result->nic) {
          nic_put(result->nic);
        }
        refcount_inc(&nic->ref);
        result->nic = nic;
        result->src = nic->addrs[addridx].a.addr;
        longest_prefix = nic->addrs[addridx].a.prefix_len;
      }
    }
    kspin_unlock(&nic->lock);
    nic_next(&nic);
  }
  if (longest_prefix > 0) {
    result->nexthop = dst;
    return true;
  }

  // No match, use the default route if we can.
  KASSERT_DBG(result->nic == NULL);
  if (g_default_route.nexthop.family == dst.family) {
    result->nexthop = g_default_route.nexthop;
    result->nic = nic_get_nm(g_default_route.nic_name);
    if (result->nic) {
      result->src.family = ADDR_UNSPEC;
      kspin_lock(&result->nic->lock);
      for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
        if (result->nic->addrs[i].a.addr.family == dst.family) {
          result->src = result->nic->addrs[0].a.addr;
          break;
        }
      }
      kspin_unlock(&result->nic->lock);
      if (result->src.family == ADDR_UNSPEC) {
        klogfm(KL_NET, WARNING,
               "unable to route packet with address family %d to default route "
               "NIC %s\n",
               dst.family, result->nic->name);
        nic_put(result->nic);
        result->nic = NULL;
        return false;
      }
    }
    return (result->nic != NULL);
  }

  // No match at all, can't route :(
  return false;
}

void ip_set_default_route(netaddr_t nexthop, const char* nic_name) {
  g_default_route.nexthop = nexthop;
  g_default_route.nic_name = nic_name;
}

void ip_get_default_route(netaddr_t* nexthop, char* nic_name) {
  *nexthop = g_default_route.nexthop;
  kstrcpy(nic_name, g_default_route.nic_name);
}
