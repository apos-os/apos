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

#define NIC_MAC_PRETTY_LEN (3 * NIC_MAC_LEN)

static list_t g_nic_list = LIST_INIT_STATIC;

static nic_t* link2nic(list_link_t* link) {
  return container_of(link, nic_t, nic_link);
}

// Pretty-print the given MAC address, using the given buffer.
static const char* mac2str(const uint8_t* mac, char* buf) {
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
    for (list_link_t* link = g_nic_list.head; link != NULL; link = link->next) {
      const nic_t* other_nic = link2nic(link);
      if (kstrcmp(nic->name, other_nic->name) == 0) {
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
  nic->nic_link = LIST_LINK_INIT;

  for (size_t i = 0; i < NIC_MAX_ADDRS; ++i) {
    kmemset(&nic->addrs[i], 0, sizeof(struct sockaddr_storage));
    nic->addrs[i].sa_family = AF_UNSPEC;
  }
}

void nic_create(nic_t* nic, const char* name_prefix) {
  char buf[NIC_MAC_PRETTY_LEN];
  find_free_name(nic, name_prefix);
  klogf("net: added NIC %s with MAC %s\n", nic->name, mac2str(nic->mac, buf));
  list_push(&g_nic_list, &nic->nic_link);
}

int nic_count(void) {
  return list_size(&g_nic_list);
}

nic_t* nic_get(int idx) {
  // TODO(aoates): allow iterating over all NICs in a way that isn't O(N^2).
  list_link_t* link = NULL;
  for (link = g_nic_list.head; idx != 0 && link != NULL; link = link->next) {
    idx--;
  }
  if (link) {
    return link2nic(link);
  } else {
    return NULL;
  }
}
