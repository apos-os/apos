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

// Definitions for POSIX's <netinet/in.h>
#ifndef APOO_USER_INCLUDE_APOS_NET_SOCKET_INET_H
#define APOO_USER_INCLUDE_APOS_NET_SOCKET_INET_H

#include <stdint.h>

#if __APOS_BUILDING_IN_TREE__
#  include "user/include/apos/net/socket/socket.h"
#else
#  include <apos/net/socket/socket.h>
#endif

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

struct in_addr {
  in_addr_t s_addr;
};

struct sockaddr_in {
  sa_family_t sin_family;   // Must be AF_INET.
  in_port_t sin_port;       // Port number.
  struct in_addr sin_addr;  // IP address.
};

struct in6_addr {
  uint8_t s6_addr[16];
};

struct sockaddr_in6 {
  sa_family_t sin6_family;    // Must be AF_INET6.
  in_port_t sin6_port;        // Port number.
  uint32_t sin6_flowinfo;     // IPv6 traffic class and flow information.
  struct in6_addr sin6_addr;  // IPv6 address.
  uint32_t sin6_scope_id;     // Set of interfaces for a scope.
};

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

// TODO(aoates): define various IPPROTO_* constants.

#define INADDR_ANY 0
// TODO(aoates): define INADDR_BROADCAST.

#endif
