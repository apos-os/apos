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

#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "user/include/apos/net/socket/unix.h"

char* inet2str(in_addr_t addr, char* buf) {
  const uint8_t* bytes = (uint8_t*)&addr;
  ksprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
  return buf;
}

struct sockaddr_in str2sin(const char* ip, int port) {
  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = str2inet(ip);
  saddr.sin_port = htob16(port);
  return saddr;
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

char* sockaddr2str(const struct sockaddr* saddr, socklen_t saddr_len,
                   char* buf) {
  switch (saddr->sa_family) {
    case AF_INET:
      if (saddr_len < (socklen_t)sizeof(struct sockaddr_in)) {
        ksprintf(buf, "<bad AF_INET addr>");
      } else {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)saddr;
        const uint8_t* bytes = (const uint8_t*)&sin->sin_addr.s_addr;
        ksprintf(buf, "%d.%d.%d.%d:%d", bytes[0], bytes[1], bytes[2], bytes[3],
                 btoh16(sin->sin_port));
      }
      break;

    case AF_UNIX:
      if (saddr_len < (socklen_t)sizeof(struct sockaddr_un) ||
          kstrnlen(((const struct sockaddr_un*)saddr)->sun_path,
                   sizeof((const struct sockaddr_un*)saddr)->sun_path) == -1) {
        ksprintf(buf, "<bad AF_UNIX addr>");
      } else {
        const struct sockaddr_un* sun = (const struct sockaddr_un*)saddr;
        kstrcpy(buf, sun->sun_path);
      }
      break;

    default:
      ksprintf(buf, "<bad sockaddr>");
      break;
  }
  return buf;
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
      addr_in->sin_port = htob16(port);
      return 0;
    }

    case ADDR_UNSPEC:
      break;
  }

  return -EAFNOSUPPORT;
}

int sock2netaddr(const struct sockaddr* saddr, socklen_t saddr_len,
                 netaddr_t* naddr, int* port) {
  if ((size_t)saddr_len < sizeof(sa_family_t)) {
    return -EINVAL;
  }
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
        *port = btoh16(addr_in->sin_port);
      }
      return 0;
    }

    case ADDR_UNSPEC:
      naddr->family = ADDR_UNSPEC;
      if (port) {
        *port = -1;
      }
      return 0;
  }

  return -EAFNOSUPPORT;
}

in_port_t get_sockaddr_port(const struct sockaddr* addr, socklen_t addr_len) {
  // We take the addr_len just to double check it rather than risk buffer
  // overflow --- this should only be called with buffers that are known to be
  // big enough.
  KASSERT(addr->sa_family == AF_INET);
  KASSERT(addr_len >= (socklen_t)sizeof(struct sockaddr_in));
  const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
  return btoh16(sin->sin_port);
}

void set_sockaddr_port(struct sockaddr* addr, socklen_t addr_len,
                       in_port_t port) {
  KASSERT(addr->sa_family == AF_INET);
  KASSERT(addr_len >= (socklen_t)sizeof(struct sockaddr_in));
  struct sockaddr_in* sin = (struct sockaddr_in*)addr;
  sin->sin_port = btoh16(port);
}

in_port_t get_sockaddrs_port(const struct sockaddr_storage* addr) {
  return get_sockaddr_port((const struct sockaddr*)addr,
                           sizeof(struct sockaddr_storage));
}

void set_sockaddrs_port(struct sockaddr_storage* addr, in_port_t port) {
  return set_sockaddr_port((struct sockaddr*)addr,
                           sizeof(struct sockaddr_storage), port);
}

void inet_make_anyaddr(int af, struct sockaddr* addr) {
  KASSERT(af == AF_INET);
  struct sockaddr_in* in_addr = (struct sockaddr_in*)addr;
  in_addr->sin_family = AF_INET;
  in_addr->sin_addr.s_addr = INADDR_ANY;
  in_addr->sin_port = 0;
}

bool inet_is_anyaddr(const struct sockaddr* addr) {
  KASSERT(addr->sa_family == AF_INET || addr->sa_family == AF_UNIX ||
          addr->sa_family == AF_UNSPEC);

  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
    return sin->sin_addr.s_addr == INADDR_ANY;
  }

  return false;
}
