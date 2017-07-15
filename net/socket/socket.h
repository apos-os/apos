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
#ifndef APOO_NET_SOCKET_SOCKET_H
#define APOO_NET_SOCKET_SOCKET_H

#include "user/include/apos/net/socket/socket.h"

struct socket_ops;
typedef struct socket_ops socket_ops_t;

// Base definition for all socket types.  Any socket type can be cast to a
// socket_t.
typedef struct {
  int s_domain;
  int s_type;
  int s_protocol;
  const socket_ops_t* s_ops;
} socket_t;

// Creates a new unbound socket, per the POSIX socket() function.
int net_socket_create(int domain, int type, int protocol, socket_t** out);

#endif
