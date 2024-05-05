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

#ifndef APOO_NET_MAC_H
#define APOO_NET_MAC_H

#include <stdint.h>

#include "common/attributes.h"

#define NIC_MAC_LEN 6        // Length of MACs
#define NIC_MAC_PRETTY_LEN (3 * NIC_MAC_LEN)

// A MAC address.
typedef struct {
  uint8_t addr[NIC_MAC_LEN];
} nic_mac_t;

// Wrapper to type-cast a raw uint8_t byte array into a nic_mac_t.
static inline ALWAYS_INLINE const nic_mac_t* raw2mac(const uint8_t* bytes) {
  return (nic_mac_t*)bytes;
}

// Pretty-print the given MAC address, using the given buffer (which must be at
// least NIC_MAC_PRETTY_LEN bytes big).
const char* mac2str(const uint8_t mac[], char* buf);

#endif
