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
#include "net/util.h"
#include "user/include/apos/net/socket/inet.h"

void net_init(void) {
  // Basic static configuration to get things going.  This should not be in the
  // kernel, and _definitely_ not be hard-coded.
  // TODO(aoates): do better than this.
  for (int nic_idx = 0; nic_idx < nic_count(); ++nic_idx) {
    nic_t* nic = nic_get(nic_idx);
    if (kstrcmp(nic->name, "eth0") == 0) {
      struct sockaddr_in* addr = (struct sockaddr_in*)&nic->addrs[0];
      addr->sin_family = AF_INET;
      addr->sin_port = 0;
      addr->sin_addr.s_addr = str2inet("10.0.2.8");
    }
  }
}
