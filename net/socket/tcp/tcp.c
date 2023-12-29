// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "net/socket/tcp/tcp.h"

#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "net/socket/tcp/internal.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

tcp_state_t g_tcp;

void tcp_init(void) {
  htbl_init(&g_tcp.connected_sockets, 8);
  g_tcp.lock = KSPINLOCK_NORMAL_INIT;
}

tcp_key_t tcp_key(const struct sockaddr* local, const struct sockaddr* remote) {
  KASSERT_DBG(local->sa_family == remote->sa_family);
  KASSERT_DBG(local->sa_family != AF_UNSPEC);

  KASSERT(local->sa_family == AF_INET);
  const struct sockaddr_in* local_sin = (const struct sockaddr_in*)local;
  const struct sockaddr_in* remote_sin = (const struct sockaddr_in*)remote;
  uint32_t vals[4] = {local_sin->sin_addr.s_addr, local_sin->sin_port,
                      remote_sin->sin_addr.s_addr, remote_sin->sin_port};
  return fnv_hash_array(vals, sizeof(vals));
}

int tcp_num_connected_sockets(void) {
  kspin_lock(&g_tcp.lock);
  int result = htbl_size(&g_tcp.connected_sockets);
  kspin_unlock(&g_tcp.lock);
  return result;
}
