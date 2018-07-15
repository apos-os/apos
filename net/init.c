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

#include "net/init.h"

#include "common/kstring.h"
#include "dev/net/nic.h"
#include "dev/net/loopback.h"
#include "net/util.h"
#include "user/include/apos/net/socket/inet.h"

void net_init(void) {
  // Basic static configuration to get things going.  This should not be in the
  // kernel, and _definitely_ not be hard-coded.
  // TODO(aoates): do better than this.
  nic_t* lo = loopback_create();
  lo->addrs[0].addr.family = ADDR_INET;
  lo->addrs[0].addr.a.ip4.s_addr = str2inet("127.0.0.1");
  lo->addrs[0].prefix_len = 8;

  nic_t* nic = nic_get_nm("eth0");
  if (nic) {
    nic->addrs[0].addr.family = ADDR_INET;
    nic->addrs[0].addr.a.ip4.s_addr = str2inet("10.0.2.8");
    nic->addrs[0].prefix_len = 24;
  }
}
