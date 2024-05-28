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
#include "net/ip/ip6_addr.h"

#include "common/kassert.h"
#include "net/addr.h"

int ip6_common_prefix(const struct in6_addr* A, const struct in6_addr* B) {
  int i = 0;
  for (i = 0; i < 16; ++i) {
    if (A->s6_addr[i] != B->s6_addr[i]) {
      break;
    }
  }
  int result = i * 8;
  if (i < 16) {
    uint8_t diff = A->s6_addr[i] ^ B->s6_addr[i];
    while (!(diff & 0x80)) {
      result++;
      diff <<= 1;
    }
  }
  return result;
}

// Constants to match the scope field in multicast addresses.
#define SCOPE_LINK_LOCAL 2
#define SCOPE_GLOBAL 0xe

static int get_scope(const struct in6_addr* addr) {
  if (addr->s6_addr[0] == 0xff) {
    // Multicast address.
    return addr->s6_addr[1] & 0x0f;
  }
  if (addr->s6_addr[0] == 0xfe && (addr->s6_addr[1] & 0xc0) == 0x80) {
    return SCOPE_LINK_LOCAL;
  }
  return SCOPE_GLOBAL;
}

#define PREFER_A 1
#define PREFER_B (-1)
int ip6_src_addr_cmp(const nic_addr_t* A, const nic_addr_t* B,
                     const netaddr_t* dst, const nic_t* out_nic) {
  KASSERT_DBG(A->a.addr.family == AF_INET6);
  KASSERT_DBG(B->a.addr.family == AF_INET6);
  KASSERT_DBG(dst->family == AF_INET6);
  // This shouldn't strictly be necessary, but short-circuit fast path.
  if (netaddr_eq(&A->a.addr, &B->a.addr)) {
    return 0;
  }

  // Rule 1: prefer equal addresses.
  if (netaddr_eq(&A->a.addr, dst)) {
    return PREFER_A;
  } else if (netaddr_eq(&B->a.addr, dst)) {
    return PREFER_B;
  }

  // Rule 2: prefer appropriate scope.
  //  If Scope(SA) < Scope(SB): If Scope(SA) < Scope(D), then prefer SB and
  //  otherwise prefer SA.  Similarly, if Scope(SB) < Scope(SA): If
  //  Scope(SB) < Scope(D), then prefer SA and otherwise prefer SB.
  int scopeA = get_scope(&A->a.addr.a.ip6);
  int scopeB = get_scope(&B->a.addr.a.ip6);
  int scopeD = get_scope(&dst->a.ip6);
  if (scopeA < scopeB) {
    if (scopeA < scopeD) return PREFER_B;
    else return PREFER_A;
  } else if (scopeB < scopeA) {
    if (scopeB < scopeD) return PREFER_A;
    else return PREFER_B;
  }

  // TODO(ipv6): implement the rest of the algorithm.
  return 0;
}
