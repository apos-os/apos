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
#include "net/util.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

typedef struct {
  const char* prefix;
  int prefix_len;
  int label;
} policy_entry_t;

// Default policy table values, from RFC 6724:
static policy_entry_t kDefaultPolicy[] = {
    {"::1", 128, 0},        //
    {"::", 0, 1},           //
    {"::ffff:0:0", 96, 4},  //
    {"2002::", 16, 2},      //
    {"2001::", 32, 5},      //
    {"fc00::", 7, 13},      //
    {"::", 96, 3},          //
    {"fec0::", 10, 11},     //
    {"3ffe::", 16, 12},     //
    {NULL, 0, 0},           //
};

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

static int get_label(const netaddr_t* addr) {
  int label = -1;
  int longest_match = -1;
  // TODO(aoates): don't parse this every time!
  for (int i = 0; kDefaultPolicy[i].prefix != NULL; ++i) {
    network_t prefix;
    prefix.addr.family = AF_INET6;
    KASSERT(0 == str2inet6(kDefaultPolicy[i].prefix, &prefix.addr.a.ip6));
    prefix.prefix_len = kDefaultPolicy[i].prefix_len;
    if (netaddr_match(addr, &prefix) && prefix.prefix_len > longest_match) {
      label = kDefaultPolicy[i].label;
      longest_match = prefix.prefix_len;
    }
  }
  if (label < 0) {
    KLOG(DFATAL, "IPv6: default policy table failed to match address\n");
    return 0;
  }
  return label;
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

  // Rule 3: avoid deprecated addresses
  // TODO(ipv6): implement SLAAC and deprecated address handling.

  // Rule 4: prefer home addresses; skipped.
  // Rule 5: prefer outgoing interface; skipped (assumed all addrs are on
  // outgoing interface).

  // Rule 6: match labels.
  int labelA = get_label(&A->a.addr);
  int labelB = get_label(&B->a.addr);
  int labelD = get_label(dst);
  if (labelA == labelD && labelB != labelD) {
    return PREFER_A;
  } else if (labelB == labelD && labelA != labelD) {
    return PREFER_B;
  }

  // Rule 7: prefer temporary addresses; skipped.
  // TODO(ipv6): implement the rest of the algorithm.
  return 0;
}
