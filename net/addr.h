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

#ifndef APOO_NET_ADDR_H
#define APOO_NET_ADDR_H

#include <stdbool.h>

#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

#define NETADDR_PRETTY_LEN INET6_PRETTY_LEN

// Address family.  Corresponds to AF_* values, but as an enum.
typedef enum {
  ADDR_UNSPEC = AF_UNSPEC,
  ADDR_INET = AF_INET,
  ADDR_INET6 = AF_INET6,
} addrfam_t;

// A generic network address, agnostic to the underlying protocol.
typedef struct {
  addrfam_t family;
  union {
    struct in_addr ip4;
    struct in6_addr ip6;
  } a;
} netaddr_t;

// A network spec (for IP, address plus netmask).
typedef struct {
  netaddr_t addr;  // The address or prefix.
  int prefix_len;  // Length of the network's prefix (i.e. netmask)
} network_t;

bool netaddr_eq(const netaddr_t* a, const netaddr_t* b);
bool netaddr_match(const netaddr_t* addr, const network_t* network);
uint32_t netaddr_hash(const netaddr_t* a);

// buf must be at least NETADDR_PRETTY_LEN bytes big.
char* netaddr2str(const netaddr_t* a, char* buf);

#endif
