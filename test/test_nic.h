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

// Utilities for manipulating NICs for testing network code.
#ifndef APOO_TEST_TEST_NIC_H
#define APOO_TEST_TEST_NIC_H

#include "dev/net/nic.h"
#include "dev/net/tuntap.h"  // For flag definitions.
#include "net/mac.h"
#include "user/include/apos/dev.h"

// A TUN/TAP device set up for testing.
typedef struct {
  nic_t* n;
  char mac[NIC_MAC_PRETTY_LEN];
  int fd;  // FD to read/write packets from.

  apos_dev_t nic_id;
} test_ttap_t;

// Create and destroy a TUN/TAP device for testing.
int test_ttap_create(test_ttap_t* t, int flags);
void test_ttap_destroy(test_ttap_t* t);

// Adds an IPv4 or IPv6 address to the given NIC.  The NIC must be locked.
// Returns the nic_addr_t for tests that need to further modify it.
nic_addr_t* nic_add_addr(nic_t* nic, const char* ipv4, int prefix_len,
                         nic_addr_state_t state);
nic_addr_t* nic_add_addr_v6(nic_t* nic, const char* ipv6, int prefix_len,
                            nic_addr_state_t state);

#endif
