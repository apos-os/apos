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

// Constants and types required by POSIX to be defined in <sys/socket.h>
#ifndef APOO_USER_NET_SOCKET_SOCKET_H
#define APOO_USER_NET_SOCKET_SOCKET_H

typedef int socklen_t;
typedef unsigned int sa_family_t;

struct sockaddr {
  sa_family_t sa_family;  // Address family.
  char sa_data[];         // Socket address (variable-length data).
};

struct sockaddr_storage {
  sa_family_t sa_family;  // Address family.
  char _sa_pad[108];
};

#define SOCK_STREAM 1     // Byte­stream socket.
#define SOCK_DGRAM 2      // Datagram socket
#define SOCK_RAW 3        // Raw socket.
// TODO(aoates): define SOCK_SEQPACKET.

#define AF_UNSPEC 1  // Unspecified.
#define AF_UNIX 2    // UNIX domain sockets.
#define AF_INET 3    // IPv4 sockets.
// TODO(aoates): define AF_INET6

#define SHUT_RD 1    // Disables further receive operations.
#define SHUT_RDWR 2  // Disables further send and receive operations.
#define SHUT_WR 3    // Disables further send operations.

// Socket options.
#define SOL_SOCKET 0xffff
#define SO_TYPE 1
#define SO_RCVBUF 2
#define SO_SNDBUF 3

// TODO(aoates): this is supposed to define size_t and ssize_t.

#define SOMAXCONN 128

#endif
