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

// Raw sockets.
#ifndef APOO_NET_SOCKET_RAW_H
#define APOO_NET_SOCKET_RAW_H

#include "net/socket/socket.h"

typedef struct socket_raw {
  socket_t base;
} socket_raw_t;

// Create a raw socket.
int sock_raw_create(int domain, int type, int protocol, socket_t** out);

#endif
