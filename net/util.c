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

#include "net/util.h"

#include <stdbool.h>

#include "common/errno.h"
#include "common/kprintf.h"
#include "common/kstring.h"

char* inet2str(in_addr_t addr, char* buf) {
  const uint8_t* bytes = (uint8_t*)&addr;
  ksprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
  return buf;
}

static bool atol_internal(const char** s, long* out) {
  *out = 0;
  // Use do/while to fail if we _start_ with a period or NULL.
  do {
    if (!kisdigit(**s)) {
      return false;
    }
    *out = *out * 10 + (**s - '0');
    (*s)++;
  } while (**s && **s != '.');
  return true;
}

in_addr_t str2inet(const char* s) {
  // TODO(aoates): rewrite this with strtol.
  uint8_t bytes[4];

  for (int i = 0; i < 4; ++i) {
    long val;
    if (!atol_internal(&s, &val)) {
      return 0;  // Unparseable as number!
    }
    if (val < 0 || val > (long)UINT8_MAX) {
      return 0;  // Out of range!
    }
    if (*s != '.' && i < 3) {
      return 0;  // Non-period in the middle!
    } else if (*s != 0 && i == 3) {
      return 0;  // Too long!
    }
    s++;  // Skip the period.
    bytes[i] = val;
  }

  in_addr_t addr;
  kmemcpy(&addr, bytes, 4);
  return addr;
}

int net2sockaddr(const netaddr_t* naddr, int port, void* saddr,
                 socklen_t saddr_len) {
  switch (naddr->family) {
    case ADDR_INET: {
      if (saddr_len < (int)sizeof(struct sockaddr_in)) {
        return -EINVAL;
      }
      struct sockaddr_in* addr_in = (struct sockaddr_in*)saddr;
      addr_in->sin_family = AF_INET;
      addr_in->sin_addr = naddr->a.ip4;
      addr_in->sin_port = port;
      return 0;
    }
  }

  return -EAFNOSUPPORT;
}

int sock2netaddr(const struct sockaddr* saddr, socklen_t saddr_len,
                 netaddr_t* naddr, int* port) {
  switch (saddr->sa_family) {
    case ADDR_INET: {
      if (saddr_len < (int)sizeof(struct sockaddr_in)) {
        return -EINVAL;
      }
      const struct sockaddr_in* addr_in = (const struct sockaddr_in*)saddr;
      if (naddr) {
        naddr->family = ADDR_INET;
        naddr->a.ip4 = addr_in->sin_addr;
      }
      if (port) {
        *port = addr_in->sin_port;
      }
      return 0;
    }
  }

  return -EAFNOSUPPORT;
}
