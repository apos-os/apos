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

#define NIC_MAX_NAME_LEN 16  // Maximum name length
#define NIC_MAC_LEN 6        // Length of MACs

typedef enum {
  NIC_ETHERNET = 1,
} nic_type_t;

typedef struct {
  char name[NIC_MAX_NAME_LEN];  // Unique human-readable name (e.g. 'eth0')
  nic_type_t type;              // What kind of NIC
  uint8_t mac[NIC_MAC_LEN];     // Hardware address.

  // Used internally.
  list_link_t nic_link;
} nic_t;

// Create a new NIC with the given name prefix.  Sets the name of the given
// nic_t, initializes internal fields, and inserts the NIC into the system
// table.
//
// TODO(aoates): come up with a better unified device model, rather than these
// type-specific registries.
void nic_create(nic_t* nic, const char* name_prefix);

#endif
