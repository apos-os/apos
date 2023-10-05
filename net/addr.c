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
#include "net/addr.h"

#include "common/attributes.h"
#include "common/endian.h"
#include "common/kassert.h"

bool netaddr_eq(const netaddr_t* a, const netaddr_t* b) {
  if (a->family != b->family) return false;
  switch (a->family) {
    case ADDR_INET:
      return a->a.ip4.s_addr == b->a.ip4.s_addr;

    case ADDR_UNSPEC:
      break;
  }

  return false;
}

static inline ALWAYS_INLINE in_addr_t netmask(int len) {
  return (len == 0) ? 0 : ~((1 << (32 - len)) - 1);
}

bool netaddr_match(const netaddr_t* addr, const network_t* network) {
  if (addr->family != network->addr.family) {
    return false;
  }
  switch (addr->family) {
    case ADDR_INET: {
      KASSERT_DBG(network->prefix_len <= 32 && network->prefix_len >= 0);
      const in_addr_t mask = htob32(netmask(network->prefix_len));
      return (addr->a.ip4.s_addr & mask) == (network->addr.a.ip4.s_addr & mask);
    }

    case ADDR_UNSPEC:
      break;
  }

  // Unknown address type.
  return false;
}
