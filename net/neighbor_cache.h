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

#ifndef APOO_NET_NEIGHBOR_CACHE_H
#define APOO_NET_NEIGHBOR_CACHE_H

#include "common/hashtable.h"
#include "dev/timer.h"
#include "net/mac.h"
#include "proc/kthread-queue.h"

typedef struct {
  htbl_t cache;
  kthread_queue_t wait;
} nbr_cache_t;

typedef struct {
  nic_mac_t mac;
  apos_ms_t last_used;
} nbr_cache_entry_t;

// Initialize an empty ARP cache.
void nbr_cache_init(nbr_cache_t* cache);

// Free all memory used by the ARP cache (but not the nbr_cache_t itself).
void nbr_cache_cleanup(nbr_cache_t* cache);

#endif
