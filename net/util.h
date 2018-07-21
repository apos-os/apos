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

#ifndef APOO_NET_UTIL_H
#define APOO_NET_UTIL_H

#include "net/addr.h"
#include "user/include/apos/net/socket/inet.h"

// How much buffer space to allocate for headers.
// TODO(aoates): this should probably be a dynamic function of some sort (and/or
// make it just a hint so pbuf_t can expand if necessary).
#define INET_HEADER_RESERVE (14 /* eth */ + 20 /* ipv4 */)

// Minimum length of a buffer for pretty-printing an IPv4 address.
#define INET_PRETTY_LEN (4 * 4)

// TODO(aoates): should these go somewhere that can be shared with userspace
// libraries?

// Pretty-print an inet address.
char* inet2str(in_addr_t addr, char* buf);

// Parse an inet address.  Returns 0 if unparseable.
in_addr_t str2inet(const char* s);

// Convert a netaddr_t and port to a struct sockaddr, and vice versa.  |saddr|
// should point to a `struct sockaddr` (void* used to prevent casts).  Returns 0
// on success.
int net2sockaddr(const netaddr_t* naddr, int port, void* saddr,
                 socklen_t saddr_len);

// Either naddr or port may be NULL.
int sock2netaddr(const struct sockaddr* saddr, socklen_t saddr_len,
                 netaddr_t* naddr, int* port);

#endif
