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

#include "net/socket/unix.h"

#include "memory/kmalloc.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/socket.h"

int sock_unix_create(int type, int protocol, socket_t** out) {
  if (type != SOCK_STREAM) {
    return -EPROTOTYPE;
  } else if (protocol != 0) {
    return -EPROTONOSUPPORT;
  }

  socket_unix_t* sock = (socket_unix_t*)kmalloc(sizeof(socket_unix_t));
  if (!sock) {
    return -ENOMEM;
  }

  sock->base.s_domain = AF_UNIX;
  sock->base.s_type = type;
  sock->base.s_protocol = protocol;
  sock->base.s_ops = NULL;  // TODO(aoates)
  *out = &sock->base;
  return 0;
}
