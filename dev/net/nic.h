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

#include "common/list.h"
#include "common/refcount.h"
#include "net/addr.h"
#include "net/mac.h"
#include "net/neighbor_cache.h"
#include "net/pbuf.h"
#include "proc/spinlock.h"

#define NIC_MAX_NAME_LEN 16  // Maximum name length
#define NIC_MAX_ADDRS 6      // Maximum number of addresses per NIC

struct nic;
typedef struct nic nic_t;

typedef struct {
  bool autoconfigure;
} nic_ipv6_options_t;

typedef enum {
  NIC_ADDR_NONE,
  NIC_ADDR_TENTATIVE,
  NIC_ADDR_ENABLED,
} nic_addr_state_t;

typedef struct {
  network_t a;
  nic_addr_state_t state;
} nic_addr_t;

typedef struct {
  // Enqueue the given packet (which should be an L2 frame) for transmission.
  // Returns 0 on success.
  int (*nic_tx)(nic_t* nic, pbuf_t* buf);

  // Clean up the NIC and free any memory (including the nic_t itself, if
  // necessary).
  void (*nic_cleanup)(nic_t* nic);

  // Subscribe or unsubscribe from a hardware multicast address.
  void (*nic_mc_sub)(nic_t* nic, const nic_mac_t* mac);
  void (*nic_mc_unsub)(nic_t* nic, const nic_mac_t* mac);
} nic_ops_t;

typedef enum {
  NIC_UNKNOWN = 0,
  NIC_ETHERNET = 1,
  NIC_LOOPBACK = 2,
  NIC_TUN = 3,
} nic_type_t;

// IPv6-specific NIC data.
typedef struct {
  nic_ipv6_options_t opts;
  htbl_t multicast;  // Multicast addresses we're subscribed to.
} nic_ipv6_t;

struct nic {
  kspinlock_t lock;

  // Fields maintained by the NIC driver.  Should be const after construction.
  char name[NIC_MAX_NAME_LEN];  // Unique human-readable name (e.g. 'eth0')
  nic_type_t type;              // What kind of NIC
  nic_mac_t mac;                // Hardware address.
  nic_ops_t* ops;

  // Fields maintained by the network subsystem.
  refcount_t ref;  // External refcount (will be zero usually).
  nic_addr_t addrs[NIC_MAX_ADDRS];  // Configured network addresses
  nbr_cache_t nbr_cache;
  nic_ipv6_t ipv6;
  list_link_t link;  // Protected by global mutex, not |lock|.
  bool deleted;      // Protected by global mutex, not |lock|.
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

// Delete the given NIC.  It will no longer be used (returned for iterations
// through the NIC list), but there may still be concurrent accesses to it.
// Once the concurrent accesses are complete and there are no active references,
// the NIC's cleanup method will be called.
//
// Does not consume a reference.
void nic_delete(nic_t* nic);

// Returns the first configured NIC (with a reference), or NULL.
nic_t* nic_first(void);

// Iterates the given pointer, transferring the reference to the next NIC.  Sets
// it to NULL if there are no more NICs to iterate through.
void nic_next(nic_t** iter);

// Returns the NIC with the given name (with a reference), or NULL.
nic_t* nic_get_nm(const char* name);

// Puts a NIC (returns the reference taken by one of the above).  The caller
// must not reference the nic_t after calling this.
void nic_put(nic_t* nic);

#endif
