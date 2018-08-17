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

#include "net/socket/sockmap.h"

#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/unix.h"

typedef struct {
  struct sockaddr_storage addr;
  socket_t* socket;
  list_link_t link;
} sm_entry_t;

// TODO(aoates): these helpers are probably useful elsewhere.  Refactor them
// out.
static size_t sizeof_addr(const struct sockaddr* addr) {
  switch (addr->sa_family) {
    case AF_INET: return sizeof(struct sockaddr_in);
  }
  klogfm(KL_NET, WARNING, "unknown address family: %d\n", addr->sa_family);
  return 0;
}

static bool is_any(const struct sockaddr* addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return ((struct sockaddr_in*)addr)->sin_addr.s_addr == INADDR_ANY;
  }
  klogfm(KL_NET, WARNING, "unknown address family: %d\n", addr->sa_family);
  return false;
}

static in_port_t get_port(const struct sockaddr* addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return ((struct sockaddr_in*)addr)->sin_port;
  }
  klogfm(KL_NET, WARNING, "unknown address family: %d\n", addr->sa_family);
  return 0;
}

static in_port_t equal(const struct sockaddr* A, const struct sockaddr* B) {
  KASSERT(A->sa_family == B->sa_family);
  switch (A->sa_family) {
    case AF_INET:
      return ((struct sockaddr_in*)A)->sin_addr.s_addr ==
             ((struct sockaddr_in*)B)->sin_addr.s_addr;
  }
  klogfm(KL_NET, WARNING, "unknown address family: %d\n", A->sa_family);
  return false;
}

sockmap_t* sockmap_create(sa_family_t family) {
  sockmap_t* sm = (sockmap_t*)kmalloc(sizeof(sockmap_t));
  if (!sm) return NULL;

  KASSERT(family == AF_INET);
  sm->family = family;
  sm->socks = LIST_INIT;
  return sm;
}

bool sockmap_insert(sockmap_t* sm, const struct sockaddr* addr,
                    socket_t* socket) {
  KASSERT(sm->family == addr->sa_family);
  if (sockmap_find(sm, addr) != NULL) {
    return false;
  }
  sm_entry_t* entry = (sm_entry_t*)kmalloc(sizeof(sm_entry_t));
  kmemcpy(&entry->addr, addr, sizeof_addr(addr));
  entry->socket = socket;
  entry->link = LIST_LINK_INIT;
  list_push(&sm->socks, &entry->link);
  return true;
}

socket_t* sockmap_find(const sockmap_t* sm, const struct sockaddr* addr) {
  KASSERT(sm->family == addr->sa_family);
  list_link_t* link = sm->socks.head;
  const in_port_t port = get_port(addr);
  while (link) {
    const sm_entry_t* entry = container_of(link, sm_entry_t, link);
    KASSERT_DBG(entry->addr.sa_family == sm->family);
    if (get_port((struct sockaddr*)&entry->addr) != port) {
      continue;
    }

    // Ports match!
    if (is_any((struct sockaddr*)&entry->addr) || is_any(addr) ||
        equal((struct sockaddr*)&entry->addr, addr)) {
      return entry->socket;
    }

    link = link->next;
  }

  return NULL;
}

socket_t* sockmap_remove(sockmap_t* sm, const struct sockaddr* addr) {
  KASSERT(sm->family == addr->sa_family);
  list_link_t* link = sm->socks.head;
  const in_port_t port = get_port(addr);
  while (link) {
    sm_entry_t* entry = container_of(link, sm_entry_t, link);
    KASSERT_DBG(entry->addr.sa_family == sm->family);
    if (get_port((struct sockaddr*)&entry->addr) != port) {
      continue;
    }

    // Ports match!
    if (equal((struct sockaddr*)&entry->addr, addr)) {
      socket_t* sock = entry->socket;
      list_remove(&sm->socks, &entry->link);
      kfree(entry);
      return sock;
    }

    link = link->next;
  }

  return NULL;
}
