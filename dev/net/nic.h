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

#ifndef APOO_DEV_NET_NIC_H
#define APOO_DEV_NET_NIC_H

#include <stdint.h>

#include "common/list.h"
#include "net/eth/arp/arp_cache.h"
#include "net/addr.h"
#include "net/pbuf.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

#define NIC_MAX_NAME_LEN 16  // Maximum name length
#define NIC_MAC_LEN 6        // Length of MACs
#define NIC_MAC_PRETTY_LEN (3 * NIC_MAC_LEN)
#define NIC_MAX_ADDRS 3      // Maximum number of addresses per NIC

// Pretty-print the given MAC address, using the given buffer (which must be at
// least NIC_MAC_PRETTY_LEN bytes big).
const char* mac2str(const uint8_t* mac, char* buf);

struct nic;
typedef struct nic nic_t;

typedef struct {
  // Enqueue the given packet (which should be an L2 frame) for transmission.
  // Returns 0 on success.
  int (*nic_tx)(nic_t* nic, pbuf_t* buf);
} nic_ops_t;

typedef enum {
  NIC_UNKNOWN = 0,
  NIC_ETHERNET = 1,
} nic_type_t;

struct nic {
  // Fields maintained by the NIC driver.
  char name[NIC_MAX_NAME_LEN];  // Unique human-readable name (e.g. 'eth0')
  nic_type_t type;              // What kind of NIC
  uint8_t mac[NIC_MAC_LEN];     // Hardware address.
  nic_ops_t* ops;

  // Fields maintained by the network subsystem.
  network_t addrs[NIC_MAX_ADDRS];  // Configured network addresses
  arp_cache_t arp_cache;

  // Fields used internally for NIC management.
  list_link_t nic_link;
};

// Initialize a nic_t structure.  Call this before calling nic_create().
void nic_init(nic_t* nic);

// Create a new NIC with the given name prefix.  Sets the name of the given
// nic_t, initializes internal fields, and inserts the NIC into the system
// table.
//
// TODO(aoates): come up with a better unified device model, rather than these
// type-specific registries.
void nic_create(nic_t* nic, const char* name_prefix);

// Returns the number of configured NICs.
int nic_count(void);

// Returns the NIC at the given index, or NULL.
nic_t* nic_get(int idx);

#endif
