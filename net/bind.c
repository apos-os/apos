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

#include "net/bind.h"

#include "common/errno.h"
#include "dev/net/nic.h"

int inet_bindable(const netaddr_t* addr) {
  switch (addr->family) {
    case AF_INET:
      if (addr->a.ip4.s_addr == INADDR_ANY) return 0;
      break;

    case AF_UNSPEC:
      break;  // Will error out.
  }
  for (int nicidx = 0; nicidx < nic_count(); ++nicidx) {
    nic_t* nic = nic_get(nicidx);
    for (int addridx = 0; addridx < NIC_MAX_ADDRS; ++addridx) {
      if (netaddr_eq(&nic->addrs[addridx].addr, addr)) {
        return 0;
      }
    }
  }

  return -EADDRNOTAVAIL;
}

int inet_choose_bind(addrfam_t family, netaddr_t* addr_out) {
  for (int nicidx = 0; nicidx < nic_count(); ++nicidx) {
    nic_t* nic = nic_get(nicidx);
    for (int addridx = 0; addridx < NIC_MAX_ADDRS; ++addridx) {
      if (nic->addrs[addridx].addr.family == family) {
        *addr_out = nic->addrs[addridx].addr;
        return nicidx;
      }
    }
  }
  return -EAFNOSUPPORT;
}
