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

#include <stdbool.h>

#include "net/addr.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"

// How much buffer space to allocate for headers.
// TODO(aoates): this should probably be a dynamic function of some sort (and/or
// make it just a hint so pbuf_t can expand if necessary).
#define INET_HEADER_RESERVE (14 /* eth */ + 20 /* ipv4 */)
#define INET6_HEADER_RESERVE (14 /* eth */ + 40 /* ipv6 */)

// Minimum length of a buffer for pretty-printing an IPv4/IPv6 address.
#define INET_PRETTY_LEN (4 * 4)
#define INET6_PRETTY_LEN (8 * 5)

// TODO(aoates): should these go somewhere that can be shared with userspace
// libraries?

// Pretty-print an inet address.
char* inet2str(in_addr_t addr, char* buf);

// Parse an inet address.  Returns 0 if unparseable.
in_addr_t str2inet(const char* s);

// Create a sockaddr_in from an IP string and port.
struct sockaddr_in str2sin(const char* ip, int port);

// As above, but for IPv6 addresses.
char* inet62str(const struct in6_addr* addr, char* buf);
int str2inet6(const char* s, struct in6_addr* addr_out);
int str2sin6(const char* ip, int port, struct sockaddr_in6* addr_out);

#define SOCKADDR_PRETTY_LEN 109

// Pretty-print a generic sockaddr.
char* sockaddr2str(const struct sockaddr* saddr, socklen_t saddr_len,
                   char* buf);

// Returns the size of the given struct sockaddr based on its family.
socklen_t sizeof_sockaddr(sa_family_t sa_family);

// Convert a netaddr_t and port to a struct sockaddr, and vice versa.  |saddr|
// should point to a `struct sockaddr` (void* used to prevent casts).  Returns 0
// on success.
int net2sockaddr(const netaddr_t* naddr, int port, void* saddr,
                 socklen_t saddr_len);

// Either naddr or port may be NULL.
int sock2netaddr(const struct sockaddr* saddr, socklen_t saddr_len,
                 netaddr_t* naddr, int* port);

// Extract or set the port in a sockaddr.  The sockaddr _must_ be an INET
// sockaddr of some sort and be valid length.  Port is native byte order.
in_port_t get_sockaddr_port(const struct sockaddr* addr, socklen_t addr_len);
void set_sockaddr_port(struct sockaddr* addr, socklen_t addr_len,
                       in_port_t port);

// Convenience versions for struct sockaddr_storage.
in_port_t get_sockaddrs_port(const struct sockaddr_storage* addr);
void set_sockaddrs_port(struct sockaddr_storage* addr, in_port_t port);

// Create an any-addr for the given address family.
void inet_make_anyaddr(int af, struct sockaddr* addr);

// Returns true if the given address is an any-addr for its family.
bool in6_is_any(const struct in6_addr* addr);
bool inet_is_anyaddr(const struct sockaddr* addr);
bool netaddr_is_anyaddr(const netaddr_t* addr);

#endif
