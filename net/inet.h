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

#ifndef APOO_NET_INET_H
#define APOO_NET_INET_H

#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

// Minimum and maximum ports.
#define INET_PORT_ANY 0
#define INET_PORT_MIN 1
#define INET_PORT_MAX 65535

// Range of ephemeral ports.  This should be configurable.
#define INET_PORT_EPHMIN 32768
#define INET_PORT_EPHMAX 65535

// Variant of sockaddr_storage that only holds enough for an IPv4 or IPv6 addr.
struct sockaddr_storage_ip {
  sa_family_t sa_family;  // Address family.
  char _sa_pad[25];
};

_Static_assert(sizeof(struct sockaddr_storage_ip) >=
               sizeof(struct sockaddr_in), "sockaddr_storage_ip too small");
_Static_assert(sizeof(struct sockaddr_storage_ip) >=
               sizeof(struct sockaddr_in6), "sockaddr_storage_ip too small");

#endif
