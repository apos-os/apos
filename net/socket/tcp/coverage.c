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
#include "net/socket/tcp/coverage.h"

#include <stdbool.h>

#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "net/socket/tcp/socket.h"
#include "proc/spinlock.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

// A representation of the state of a TCP socket.
typedef struct {
  socktcp_state_t state;
  bool has_recv_data;  // Do we have received data buffered?
  bool has_send_data;  // Do we have unsent data buffered?
  bool has_children;   // For sockets in LISTEN, do we have children buffered?
  bool recv_shutdown;
  bool send_shutdown;
} tcp_coverage_state_t;

typedef struct {
  tcp_coverage_state_t state;
  htbl_t events;  // map of { hash -> const char* }
} coverage_entry_t;

// Map of { hash(tcp_coverage_state_t) -> coverage_entry_t* }
static htbl_t g_tcp_coverage;
static bool g_tcp_coverage_init = false;

static uint32_t state_key(const tcp_coverage_state_t* state) {
  uint32_t h = fnv_hash(state->state);
  h = fnv_hash_concat(h, (uint32_t)state->has_recv_data);
  h = fnv_hash_concat(h, (uint32_t)state->has_send_data);
  h = fnv_hash_concat(h, (uint32_t)state->has_children);
  h = fnv_hash_concat(h, (uint32_t)state->recv_shutdown);
  h = fnv_hash_concat(h, (uint32_t)state->send_shutdown);
  return h;
}

static void do_init_state(const tcp_coverage_state_t* state) {
  coverage_entry_t* entry = KMALLOC(coverage_entry_t);
  entry->state = *state;
  htbl_init(&entry->events, 10);
  htbl_put(&g_tcp_coverage, state_key(state), entry);
}

static void tcp_coverage_init(void) {
  KASSERT_DBG(g_tcp_coverage_init == false);
  g_tcp_coverage_init = true;
  htbl_init(&g_tcp_coverage, 100);

  tcp_coverage_state_t cstate;
  for (socktcp_state_t i = 0; i <= TCP_STATE_MAX; ++i) {
    cstate.state = i;

    for (int rdata = 0; rdata < 2; rdata++) {
      for (int sdata = 0; sdata < 2; sdata++) {
        for (int child = 0; child < (i == TCP_LISTEN ? 2 : 1); child++) {
          for (int rshut = 0; rshut < 2; rshut++) {
            for (int sshut = 0; sshut < 2; sshut++) {
              cstate.has_recv_data = rdata;
              cstate.has_send_data = sdata;
              cstate.has_children = child;
              cstate.recv_shutdown = rshut;
              cstate.send_shutdown = sshut;
              do_init_state(&cstate);
            }
          }
        }
      }
    }
  }
}

void tcp_coverage_log_do(const char* event, const socket_tcp_t* socket) {
  KASSERT_DBG(kspin_is_held(&socket->spin_mu));
  if (!g_tcp_coverage_init) {
    tcp_coverage_init();
  }

  tcp_coverage_state_t state;
  state.state = socket->state;
  state.has_recv_data = (socket->recv_buf.len > 0);
  state.has_send_data = (socket->send_buf.len > 0);
  state.has_children = (!list_empty(&socket->children_connecting) ||
                        !list_empty(&socket->children_established));
  state.recv_shutdown = socket->recv_shutdown;
  state.send_shutdown = socket->send_shutdown;
  uint32_t key = state_key(&state);
  void* val;
  if (htbl_get(&g_tcp_coverage, key, &val) != 0) {
    KLOG(DFATAL, "TCP coverage: socket %p in unknown state\n", socket);
    return;
  }
  coverage_entry_t* entry = (coverage_entry_t*)val;
  KASSERT_DBG(state_key(&entry->state) == key);
  htbl_put(&entry->events, fnv_hash_string(event), (void*)event);
}

static void dump_events(void* arg, htbl_key_t key, void* val) {
  bool* first = (bool*)arg;
  if (*first) {
    *first = false;
  } else {
    KLOG(INFO, ",");
  }
  KLOG(INFO, "%s", (const char*)val);
}

static void dump_entry(void* arg, htbl_key_t key, void* val) {
  const coverage_entry_t* entry = (const coverage_entry_t*)val;
  KLOG(INFO, "  state=%s "
       "has_recv_data=%d "
       "has_send_data=%d "
       "has_children=%d "
       "recv_shutdown=%d "
       "send_shutdown=%d : ",
       tcp_state2str(entry->state.state),
       entry->state.has_recv_data,
       entry->state.has_send_data,
       entry->state.has_children,
       entry->state.recv_shutdown,
       entry->state.send_shutdown);
  bool first = true;
  htbl_iterate(&entry->events, &dump_events, &first);
  KLOG(INFO, "\n");
}

void tcp_coverage_dump(void) {
  if (!g_tcp_coverage_init) {
    return;
  }
  KLOG(INFO, "TCP coverage data:\n");
  htbl_iterate(&g_tcp_coverage, &dump_entry, NULL);
}
