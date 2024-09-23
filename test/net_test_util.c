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
#include "test/net_test_util.h"

#include "common/kassert.h"
#include "proc/spinlock.h"

void disable_nic_gateways(saved_gw_nics_t* gwn) {
  int i = 0;
  for (i = 0; i < MAX_SAVED_NICS; ++i) {
    gwn->gw_nics[i] = NULL;
  }
  nic_t* nic = nic_first();
  i = 0;
  while (nic) {
    kspin_lock(&nic->lock);
    if (nic->ipv6.gateway.valid) {
      KASSERT(i < MAX_SAVED_NICS);
      nic_ref(nic);
      gwn->gw_nics[i++] = nic;
      nic->ipv6.gateway.valid = false;
    }
    kspin_unlock(&nic->lock);
    nic_next(&nic);
  }
}

void restore_nic_gateways(saved_gw_nics_t* gwn) {
  int i = 0;
  for (i = 0; i < MAX_SAVED_NICS; ++i) {
    if (!gwn->gw_nics[i]) {
      continue;
    }

    nic_t* nic = gwn->gw_nics[i];
    kspin_lock(&nic->lock);
    nic->ipv6.gateway.valid = true;
    kspin_unlock(&nic->lock);
    nic_put(nic);
    gwn->gw_nics[i] = NULL;
  }
}
