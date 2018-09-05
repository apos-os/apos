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

#include "net/ip/util.h"

#include "common/errno.h"
#include "net/ip/route.h"
#include "net/util.h"

int ip_pick_src(const struct sockaddr* dst, socklen_t dst_len,
                struct sockaddr_storage* src_out) {
  netaddr_t ndst;
  int result = sock2netaddr(dst, dst_len, &ndst, NULL);
  if (result) return result;

  ip_routed_t route;
  if (!ip_route(ndst, &route)) {
    return -ENETUNREACH;
  }
  return net2sockaddr(&route.src, 0, src_out, sizeof(struct sockaddr_storage));
}
