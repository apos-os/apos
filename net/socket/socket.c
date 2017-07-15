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
#include "net/socket/socket.h"

#include "common/kassert.h"
#include "user/include/apos/errors.h"
#include "net/socket/unix.h"

int net_socket_create(int domain, int type, int protocol, socket_t** out) {
  int result;
  if (domain == AF_UNIX) {
    result = sock_unix_create(type, protocol, out);
  } else {
    result = -EAFNOSUPPORT;
  }
  if (result == 0) {
    KASSERT_DBG((*out)->s_domain == domain);
    KASSERT_DBG((*out)->s_type == type);
    KASSERT_DBG((*out)->s_protocol == protocol);
  }
  return result;
}
