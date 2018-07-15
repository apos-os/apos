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

#include "dev/net/nic.h"

#include <stdbool.h>

#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/list.h"

// TODO(aoates): use something more flexible (either back to a list, or an
// arraylist or hashtable based approach).
#define MAX_NICS 10
static int g_num_nics = 0;
static nic_t* g_nics[MAX_NICS];

const char* mac2str(const uint8_t* mac, char* buf) {
  ksprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
           mac[4], mac[5]);
  return buf;
}

static void find_free_name(nic_t* nic, const char* name_prefix) {
  // Allow up to 999 NICs of each type.
  const int kMaxIndex = 1000;
  KASSERT(kstrlen(name_prefix) < NIC_MAX_NAME_LEN - 4);

  // Find a free name.  This is bananas inefficient.
  int idx;
  for (idx = 0; idx < kMaxIndex; ++idx) {
    ksprintf(nic->name, "%s%d", name_prefix, idx);
    bool collision = false;
    for (int i = 0; i < g_num_nics; ++i) {
      if (kstrcmp(nic->name, g_nics[i]->name) == 0) {
        collision = true;
        break;
      }
    }
    if (!collision) {
      break;
    }
  }
  if (idx == kMaxIndex) {
    die("Too many NICs!  I can't deal!");
  }
}

void nic_init(nic_t* nic) {
  kmemset(&nic->name, 0, NIC_MAX_NAME_LEN);
  nic->type = NIC_UNKNOWN;
  kmemset(&nic->mac, 0, NIC_MAC_LEN);

  for (size_t i = 0; i < NIC_MAX_ADDRS; ++i) {
    kmemset(&nic->addrs[i], 0, sizeof(network_t));
    nic->addrs[i].addr.family = AF_UNSPEC;
  }
  arp_cache_init(&nic->arp_cache);
}

void nic_create(nic_t* nic, const char* name_prefix) {
  char buf[NIC_MAC_PRETTY_LEN];
  find_free_name(nic, name_prefix);
  KASSERT(g_num_nics < MAX_NICS);
  klogf("net: added NIC %s with MAC %s\n", nic->name, mac2str(nic->mac, buf));
  g_nics[g_num_nics++] = nic;
}

int nic_count(void) {
  return g_num_nics;
}

nic_t* nic_get(int idx) {
  return (idx >= 0 && idx < g_num_nics) ? g_nics[idx] : NULL;
}

nic_t* nic_get_nm(const char* name) {
  for (int i = 0; i < g_num_nics; ++i) {
    if (g_nics[i] && kstrcmp(name, g_nics[i]->name) == 0) {
      return g_nics[i];
    }
  }
  return NULL;
}
