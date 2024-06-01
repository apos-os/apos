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
#include "test/test_nic.h"

#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "net/util.h"
#include "proc/spinlock.h"

static nic_addr_t* alloc_addr(nic_t* nic, int prefix_len,
                              nic_addr_state_t state) {
  KASSERT(kspin_is_held(&nic->lock));
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state == NIC_ADDR_NONE) {
      nic->addrs[i].a.prefix_len = prefix_len;
      nic->addrs[i].state = state;
      return &nic->addrs[i];
    }
  }
  die("NIC has too many addresses");
}

nic_addr_t* nic_add_addr(nic_t* nic, const char* ipv4, int prefix_len,
                         nic_addr_state_t state) {
  KASSERT(kspin_is_held(&nic->lock));
  // Sanity check to make sure IPv6 addresses aren't passed.
  KASSERT(kstrchr(ipv4, ':') == 0);
  KASSERT(prefix_len >= 0);
  KASSERT(prefix_len <= 32);
  nic_addr_t* addr = alloc_addr(nic, prefix_len, state);
  addr->a.addr.family = ADDR_INET;
  addr->a.addr.a.ip4.s_addr = str2inet(ipv4);
  return addr;
}

nic_addr_t* nic_add_addr_v6(nic_t* nic, const char* ipv6, int prefix_len,
                            nic_addr_state_t state) {
  KASSERT(kspin_is_held(&nic->lock));
  // Sanity check to make sure IPv4 addresses aren't passed.
  KASSERT(kstrchr(ipv6, '.') == 0);
  KASSERT(prefix_len >= 0);
  KASSERT(prefix_len <= 128);
  nic_addr_t* addr = alloc_addr(nic, prefix_len, state);
  addr->a.addr.family = ADDR_INET6;
  KASSERT(0 == str2inet6(ipv6, &addr->a.addr.a.ip6));
  return addr;
}
