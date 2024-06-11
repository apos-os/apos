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
#include "net/inet.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/sockmap.h"
#include "proc/spinlock.h"
#include "user/include/apos/net/socket/inet.h"

tcp_state_t g_tcp;

void tcp_init(void) {
  tcpsm_init(&g_tcp.sockets, AF_INET, INET_PORT_EPHMIN, INET_PORT_EPHMAX);
  g_tcp.lock = KSPINLOCK_NORMAL_INIT;
}

tcp_key_t tcp_key(const struct sockaddr* local, const struct sockaddr* remote) {
  KASSERT_DBG(local->sa_family == remote->sa_family);
  KASSERT_DBG(local->sa_family != AF_UNSPEC);

  if (local->sa_family == AF_INET) {
    const struct sockaddr_in* local_sin = (const struct sockaddr_in*)local;
    const struct sockaddr_in* remote_sin = (const struct sockaddr_in*)remote;
    uint32_t vals[4] = {local_sin->sin_addr.s_addr, local_sin->sin_port,
                        remote_sin->sin_addr.s_addr, remote_sin->sin_port};
    return fnv_hash_array(vals, sizeof(vals));
  } else {
    KASSERT(local->sa_family == AF_INET6);
    const struct sockaddr_in6* local_sin6 = (const struct sockaddr_in6*)local;
    const struct sockaddr_in6* remote_sin6 = (const struct sockaddr_in6*)remote;
    tcp_key_t key =
        fnv_hash_array(&local_sin6->sin6_addr, sizeof(struct in6_addr));
    key = fnv_hash_concat(key, fnv_hash(local_sin6->sin6_port));
    key = fnv_hash_concat(
        key, fnv_hash_array(&remote_sin6->sin6_addr, sizeof(struct in6_addr)));
    key = fnv_hash_concat(key, fnv_hash(remote_sin6->sin6_port));
    return key;
  }
}

tcp_key_t tcp_key_single(const struct sockaddr* local) {
  KASSERT_DBG(local->sa_family != AF_UNSPEC);

  if (local->sa_family == AF_INET) {
    const struct sockaddr_in* local_sin = (const struct sockaddr_in*)local;
    uint32_t vals[2] = {local_sin->sin_addr.s_addr, local_sin->sin_port};
    return fnv_hash_array(vals, sizeof(vals));
  } else {
    KASSERT(local->sa_family == AF_INET6);
    const struct sockaddr_in6* local_sin6 = (const struct sockaddr_in6*)local;
    tcp_key_t key =
        fnv_hash_array(&local_sin6->sin6_addr, sizeof(struct in6_addr));
    key = fnv_hash_concat(key, fnv_hash(local_sin6->sin6_port));
    return key;
  }
}

int tcp_num_connected_sockets(void) {
  kspin_lock(&g_tcp.lock);
  int result = tcpsm_num_connected(&g_tcp.sockets);
  kspin_unlock(&g_tcp.lock);
  return result;
}
