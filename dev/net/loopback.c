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

#include "dev/net/loopback.h"

#include "common/klog.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "memory/kmalloc.h"

#define KLOG(...) klogfm(KL_NET, __VA_ARGS__)

nic_t* loopback_create(void) {
  nic_t* nic = kmalloc(sizeof(nic_t));
  nic_init(nic);
  nic->type = NIC_LOOPBACK;
  kmemset(nic->mac, 0, NIC_MAC_LEN);
  nic->ops = NULL;
  nic_create(nic, "lo");
  KLOG(INFO, "net: created loopback device %s\n", nic->name);
  return nic;
}
