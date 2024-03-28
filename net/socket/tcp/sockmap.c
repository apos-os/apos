// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "net/socket/tcp/sockmap.h"

#include "common/hash.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/hashtable.h"
#include "common/list.h"
#include "memory/kmalloc.h"
#include "net/inet.h"
#include "net/socket/tcp/internal.h"
#include "net/util.h"

// A single socket entry.  It duplicates all data needed for sockmap
// functionality so that this code never has to lock a socket in the map (and
// risk deadlock).
typedef struct {
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  socket_tcp_t* socket;
  list_link_t link;  // Link on the bound_sockets table.
  list_link_t port_link;  // Link on port_table.
} sm_entry_t;

// Entry for a particular 3- or 5-tuple.
typedef struct {
  list_t sockets;
} sm_list_t;

static inline ALWAYS_INLINE tcp_key_t
tcp_key_sas(const struct sockaddr_storage* local,
            const struct sockaddr_storage* remote) {
  return tcp_key((const struct sockaddr*)local, (const struct sockaddr*)remote);
}

static inline ALWAYS_INLINE tcp_key_t
tcp_key_bound(const struct sockaddr_storage* local) {
  return tcp_key_single((const struct sockaddr*)local);
}

static inline ALWAYS_INLINE bool is_any(const struct sockaddr_storage* addr) {
  return inet_is_anyaddr((const struct sockaddr*)addr);
}

static void sm_bound_dtor(void* arg, uint32_t key, void* val) {
  sm_list_t* list = (sm_list_t*)val;
  while (!list_empty(&list->sockets)) {
    sm_entry_t* entry =
        container_of(list_pop(&list->sockets), sm_entry_t, link);
    kfree(entry);
  }
  kfree(list);
}

static void sm_port_dtor(void* arg, uint32_t key, void* val) {
  kfree(val);
}

// TODO(aoates): these helpers are probably useful elsewhere.  Refactor them
// out.
static bool equal(const struct sockaddr_storage* A,
                  const struct sockaddr_storage* B) {
  KASSERT(A->sa_family == B->sa_family);
  switch (A->sa_family) {
    case AF_INET:
      return (((struct sockaddr_in*)A)->sin_addr.s_addr ==
              ((struct sockaddr_in*)B)->sin_addr.s_addr) &&
             get_sockaddrs_port(A) == get_sockaddrs_port(B);
  }
  klogfm(KL_NET, WARNING, "unknown address family: %d\n", A->sa_family);
  return false;
}

// Returns the tcp_key_t corresponding to ANY_ADDR:<port> (with the port of the
// given address).
static tcp_key_t get_anyaddr_port_key(const struct sockaddr_storage* local) {
  struct sockaddr_storage any_addr;
  inet_make_anyaddr(local->sa_family, (struct sockaddr*)&any_addr);
  set_sockaddrs_port(&any_addr, get_sockaddrs_port(local));
  return tcp_key_bound(&any_addr);
}

// Returns the port_table key for an address.
static uint32_t get_port_table_key(const struct sockaddr_storage* local) {
  return fnv_hash(get_sockaddrs_port(local));
}

// Checks if the given address pair (|remote| is optional) conflicts with any
// entries in the socket map.  Returns 0 if no conflicts, or -error.
int check_conflicts(const tcp_sockmap_t* sm,
                    const struct sockaddr_storage* local,
                    const struct sockaddr_storage* remote) {
  // If this is a full 5-tuple, then only other 5-tuple sockets can conflict.
  if (remote) {
    tcp_key_t tcpkey = tcp_key_sas(local, remote);
    void* val;
    if (htbl_get(&sm->connected_sockets, tcpkey, &val) == 0) {
      return -EADDRINUSE;
    }
  } else {
    // If no remote address, then this matches _any_ remote address.  First look
    // for anything bound to <ip>:<port>, whether it's 3-tuple or 5-tuple bound.
    tcp_key_t tcpkey = tcp_key_bound(local);
    void* val;
    if (htbl_get(&sm->bound_sockets, tcpkey, &val) == 0) {
      return -EADDRINUSE;
    }

    // No exact 3-tuple match either.  Look for an any-addr port-only match.
    tcpkey = get_anyaddr_port_key(local);
    if (htbl_get(&sm->bound_sockets, tcpkey, &val) == 0) {
      return -EADDRINUSE;
    }

    // If the new address is itself the any-address, also check if anything else
    // is currently bound to the same port.
    if (is_any(local) &&
        htbl_get(&sm->port_table, get_port_table_key(local), &val) == 0) {
      return -EADDRINUSE;
    }
  }
  return 0;
}

// Finds and returns a free port, or zero if one cannot be found.
in_port_t find_free_port(const tcp_sockmap_t* sm,
                         const struct sockaddr_storage* local_in,
                         const struct sockaddr_storage* remote) {
  struct sockaddr_storage local;
  kmemcpy(&local, local_in, sizeof(local));
  KASSERT_DBG(equal(&local, local_in));
  for (in_port_t port = sm->eph_port_min; port <= sm->eph_port_max; ++port) {
    set_sockaddrs_port(&local, port);
    if (check_conflicts(sm, &local, remote) == 0) {
      return port;
    }
  }
  return 0;
}

void tcpsm_init(tcp_sockmap_t* sm, sa_family_t family, int eph_port_min,
                int eph_port_max) {
  sm->family = family;
  sm->eph_port_min = eph_port_min;
  sm->eph_port_max = eph_port_max;
  htbl_init(&sm->bound_sockets, 10);
  htbl_init(&sm->connected_sockets, 10);
  htbl_init(&sm->port_table, 10);
}

void tcpsm_cleanup(tcp_sockmap_t* sm) {
  // Everything in |connected_sockets| is also in |bound_sockets|.
  htbl_cleanup(&sm->connected_sockets);

  htbl_clear(&sm->bound_sockets, &sm_bound_dtor, NULL);
  htbl_cleanup(&sm->bound_sockets);
  htbl_clear(&sm->port_table, &sm_port_dtor, NULL);
  htbl_cleanup(&sm->port_table);
}

static socket_tcp_t* tcpsm_find_bound(const tcp_sockmap_t* sm, tcp_key_t tcpkey,
                                      const struct sockaddr_storage* local) {
  void* val;
  if (htbl_get(&sm->bound_sockets, tcpkey, &val) == 0) {
    const sm_list_t* entry = (sm_list_t*)val;
    // Find the first entry that doesn't have a remote address set.
    FOR_EACH_LIST(iter, &entry->sockets) {
      sm_entry_t* entry = LIST_ENTRY(iter, sm_entry_t, link);
      if (!is_any(&entry->local)) {
        KASSERT_DBG(equal(&entry->local, local));
      }
      if (entry->remote.sa_family == AF_UNSPEC) {
        return entry->socket;
      }
    }
  }
  return NULL;
}

socket_tcp_t* tcpsm_find(const tcp_sockmap_t* sm,
                         const struct sockaddr_storage* local,
                         const struct sockaddr_storage* remote) {
  KASSERT(local->sa_family == sm->family);

  tcp_key_t tcpkey;
  void* val;
  if (remote) {
    KASSERT(remote->sa_family == sm->family);
    tcpkey = tcp_key_sas(local, remote);
    if (htbl_get(&sm->connected_sockets, tcpkey, &val) == 0) {
      const sm_entry_t* entry = (sm_entry_t*)val;
      KASSERT_DBG(equal(&entry->local, local));
      KASSERT_DBG(equal(&entry->remote, remote));
      return ((sm_entry_t*)val)->socket;
    }
  }

  // No full 5-tuple match.  Look for an exact 3-tuple match.
  tcpkey = tcp_key_bound(local);
  socket_tcp_t* result = tcpsm_find_bound(sm, tcpkey, local);
  if (result) {
    return result;
  }

  // No exact 5-tuple match either.  Look for an any-addr port-only match.
  tcpkey = get_anyaddr_port_key(local);
  return tcpsm_find_bound(sm, tcpkey, local);
}

int tcpsm_bind(tcp_sockmap_t* sm, struct sockaddr_storage* local,
               const struct sockaddr_storage* remote, socket_tcp_t* sock) {
  KASSERT(local->sa_family == sm->family);
  if (remote) KASSERT(remote->sa_family == sm->family);

  // Check validity of parameters.
  if (remote) {
    if (is_any(remote) || get_sockaddrs_port(remote) == INET_PORT_ANY) {
      return -EINVAL;
    }
    if (is_any(local)) {
      return -EINVAL;
    }
  }

  // Assign port if necessary.
  if (get_sockaddrs_port(local) == INET_PORT_ANY) {
    in_port_t port = find_free_port(sm, local, remote);
    if (port == 0) {
      return -EADDRINUSE;
    }
    set_sockaddrs_port(local, port);
  } else {
    // Check for conflicts.  If we assigned a port, there can definitionally be
    // no conflicts.
    int result = check_conflicts(sm, local, remote);
    if (result) {
      return result;
    }
  }

  // Insert into the socket maps.
  tcp_key_t tcpkey = tcp_key_bound(local);
  sm_entry_t* entry = KMALLOC(sm_entry_t);
  kmemcpy(&entry->local, local, sizeof(entry->local));
  if (remote) {
    kmemcpy(&entry->remote, remote, sizeof(entry->remote));
  } else {
    entry->remote.sa_family = AF_UNSPEC;
  }
  entry->socket = sock;
  entry->link = LIST_LINK_INIT;
  entry->port_link = LIST_LINK_INIT;
  void* val;
  sm_list_t* list = NULL;
  if (htbl_get(&sm->bound_sockets, tcpkey, &val) == 0) {
    list = (sm_list_t*)val;
  } else {
    list = KMALLOC(sm_list_t);
    list->sockets = LIST_INIT;
    htbl_put(&sm->bound_sockets, tcpkey, list);
  }
  list_push(&list->sockets, &entry->link);

  uint32_t port_key = get_port_table_key(local);
  if (htbl_get(&sm->port_table, port_key, &val) == 0) {
    list = (sm_list_t*)val;
  } else {
    list = KMALLOC(sm_list_t);
    list->sockets = LIST_INIT;
    htbl_put(&sm->port_table, port_key, list);
  }
  list_push(&list->sockets, &entry->port_link);

  if (remote) {
    tcpkey = tcp_key_sas(local, remote);
    htbl_put(&sm->connected_sockets, tcpkey, entry);
  }

  return 0;
}

int tcpsm_remove(tcp_sockmap_t* sm, const struct sockaddr_storage* local,
                 const struct sockaddr_storage* remote, socket_tcp_t* sock) {
  KASSERT(local->sa_family == sm->family);
  if (remote) KASSERT(remote->sa_family == sm->family);

  tcp_key_t tcpkey;
  int result;
  if (remote) {
    tcpkey = tcp_key_sas(local, remote);
    // Sanity check.
    void* val;
    if (htbl_get(&sm->connected_sockets, tcpkey, &val) == 0) {
      sm_entry_t* entry = (sm_entry_t*)val;
      KASSERT_DBG(equal(local, &entry->local));
      KASSERT_DBG(equal(remote, &entry->remote));
      KASSERT(entry->socket == sock);
    }

    result = htbl_remove(&sm->connected_sockets, tcpkey);
    if (result) {
      return -ENOENT;
    }
  }

  tcpkey = tcp_key_bound(local);
  void* val;
  if (htbl_get(&sm->bound_sockets, tcpkey, &val)) {
    return -ENOENT;
  }

  sm_list_t* list = (sm_list_t*)val;
  sm_entry_t* entry = NULL;
  bool found = false;
  FOR_EACH_LIST(iter, &list->sockets) {
    entry = LIST_ENTRY(iter, sm_entry_t, link);
    if (entry->socket == sock) {
      found = true;
      break;
    }
  }
  if (!found) {
    return -ENOENT;
  }

  // Sanity check.
  KASSERT_DBG(equal(&entry->local, local));
  if (remote) {
    KASSERT_DBG(equal(&entry->remote, remote));
  } else {
    KASSERT_DBG(entry->remote.sa_family == AF_UNSPEC);
  }

  list_remove(&list->sockets, &entry->link);
  if (list_empty(&list->sockets)) {
    KASSERT(htbl_remove(&sm->bound_sockets, tcpkey) == 0);
    kfree(list);
  }

  // Remove from the port_table.
  uint32_t port_key = get_port_table_key(local);
  KASSERT(htbl_get(&sm->port_table, port_key, &val) == 0);
  list = (sm_list_t*)val;
  list_remove(&list->sockets, &entry->port_link);
  if (list_empty(&list->sockets)) {
    KASSERT(htbl_remove(&sm->port_table, port_key) == 0);
    kfree(list);
  }

  kfree(entry);

  return 0;
}

int tcpsm_num_connected(const tcp_sockmap_t* sm) {
  return htbl_size(&sm->connected_sockets);
}
