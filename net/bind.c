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
#include "common/kassert.h"
#include "dev/net/nic.h"
#include "net/addr.h"
#include "net/util.h"
#include "proc/spinlock.h"

int inet_bindable(const netaddr_t* addr) {
  if (netaddr_is_anyaddr(addr)) {
    return 0;
  }

  nic_t* nic = nic_first();
  while (nic) {
    if (inet_source_valid(addr, nic) == 0) {
      nic_put(nic);
      return 0;
    }
    nic_next(&nic);
  }

  return -EADDRNOTAVAIL;
}

int inet_source_valid(const netaddr_t* addr, nic_t* nic) {
  kspin_lock(&nic->lock);
  for (int addridx = 0; addridx < NIC_MAX_ADDRS; ++addridx) {
    if (netaddr_eq(&nic->addrs[addridx].a.addr, addr)) {
      kspin_unlock(&nic->lock);
      return 0;
    }

    // As a special case, for loopback interfaces, allow binding to any
    // address in the configured network.
    if (nic->type == NIC_LOOPBACK &&
        netaddr_match(addr, &nic->addrs[addridx].a)) {
      kspin_unlock(&nic->lock);
      return 0;
    }
  }

  kspin_unlock(&nic->lock);
  return -EADDRNOTAVAIL;
}

int inet_choose_bind(addrfam_t family, netaddr_t* addr_out) {
  nic_t* nic = nic_first();
  while (nic) {
    kspin_lock(&nic->lock);
    for (int addridx = 0; addridx < NIC_MAX_ADDRS; ++addridx) {
      if (nic->addrs[addridx].a.addr.family == family) {
        *addr_out = nic->addrs[addridx].a.addr;
        kspin_unlock(&nic->lock);
        nic_put(nic);
        return 0;
      }
    }
    kspin_unlock(&nic->lock);
    nic_next(&nic);
  }
  return -EAFNOSUPPORT;
}
