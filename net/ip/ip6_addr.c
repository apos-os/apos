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
#include "net/ip/ip6_addr.h"

int ip6_common_prefix(const struct in6_addr* A, const struct in6_addr* B) {
  int i = 0;
  for (i = 0; i < 16; ++i) {
    if (A->s6_addr[i] != B->s6_addr[i]) {
      break;
    }
  }
  int result = i * 8;
  if (i < 16) {
    uint8_t diff = A->s6_addr[i] ^ B->s6_addr[i];
    while (!(diff & 0x80)) {
      result++;
      diff <<= 1;
    }
  }
  return result;
}
