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

#include "common/debug.h"
#include "common/endian.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "net/addr.h"
#include "user/include/apos/net/socket/unix.h"

#define KLOG(...) klogfm(KL_TCP, __VA_ARGS__)

ssize_t inet_header_reserve(sa_family_t family) {
  switch (family) {
    case AF_INET:
      return INET_HEADER_RESERVE;

    case AF_INET6:
      return INET6_HEADER_RESERVE;
  }
  KLOG(DFATAL, "Unknown address family: %d", family);
  return INET6_HEADER_RESERVE;
}

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

char* inet62str(const struct in6_addr* addr, char* buf) {
  // First find the longest string of zeroes.
  int zrun_start = -1;
  int zrun_len = 0;
  int cur_zrun_start = -1;
  int cur_zrun_len = 0;
  for (int i = 0; i < 8; ++i) {
    bool is_zero = (addr->s6_addr[i * 2] == 0 && addr->s6_addr[i * 2 + 1] == 0);
    if (is_zero) {
      if (cur_zrun_start < 0) {
        cur_zrun_start = i;
        cur_zrun_len = 0;
      }
      cur_zrun_len++;
    } else {
      if (cur_zrun_start >= 0 && cur_zrun_len > 1 && cur_zrun_len > zrun_len) {
        zrun_start = cur_zrun_start;
        zrun_len = cur_zrun_len;
      }
      cur_zrun_start = -1;
      cur_zrun_len = 0;
    }
  }
  if (cur_zrun_start >= 0 && cur_zrun_len > zrun_len) {
    zrun_start = cur_zrun_start;
    zrun_len = cur_zrun_len;
  }

  // Print the address.
  char* orig_buf = buf;
  bool colon = false;
  for (int i = 0; i < 8; ++i) {
    if (i == zrun_start) {
      kstrcpy(buf, "::");
      buf += 2;
      colon = false;
    } else if (i > zrun_start && i < zrun_start + zrun_len) {
      continue;
    } else {
      if (colon) {
        kstrcpy(buf, ":");
        buf++;
      }
      uint16_t val =
          ((uint16_t)addr->s6_addr[i * 2] << 8) + addr->s6_addr[i * 2 + 1];
      kutoa_hex_lower_r(val, buf, 5);
      buf += kstrlen(buf);
      colon = true;
    }
  }
  return orig_buf;
}

int str2inet6(const char* s, struct in6_addr* addr_out) {
  // First check the string for validity and find the double-colon, if any.
  int zrun_start = -1;
  int hextet = 0;
  int i = 0;
  bool expect_colon = false;
  while (s[i] != '\0') {
    if (hextet > 7) {
      return -EINVAL;  // Too man hextets.
    }
    int hlen = 0;
    if (expect_colon && s[i] != ':') {
      return -EINVAL;
    }
    if (s[i] == ':') {
      // Special case for a double colon at the start.
      if (i == 0 && s[1] == ':') expect_colon = true;
      if (!expect_colon) {
        return -EINVAL;
      }
      i++;
    }

    // Look for a double colon.
    if (s[i] == ':') {
      if (zrun_start >= 0) {
        return -EINVAL;  // Multiple double colons.
      }
      zrun_start = hextet;
      i++;
      expect_colon = false;
      continue;
    }
    // Find the limits of the hextet (consume up to 4 hex digits).
    while (kishex(s[i + hlen]) && hlen < 4) {
      hlen++;
    }
    if (hlen == 0) {
      return -EINVAL;
    }
    char hstr[5];
    kmemcpy(hstr, s + i, hlen);
    hstr[hlen] = '\0';
    int hextet_val = katou_hex(hstr);
    KASSERT_DBG(hextet_val >= 0);
    KASSERT_DBG(hextet_val <= (int)UINT16_MAX);
    addr_out->s6_addr[2 * hextet] = hextet_val >> 8;
    addr_out->s6_addr[2 * hextet + 1] = hextet_val;
    hextet++;
    i += hlen;
    expect_colon = true;
  }
  if (hextet < 8 && zrun_start < 0) {
    return -EINVAL;  // Too few hextets.
  }

  // If we found a double colon, shift everything to fill in the zeroes.
  if (zrun_start >= 0) {
    int zeroes = 2 * (8 - hextet);
    zrun_start *= 2;  // Switch from hextets to octets.
    for (i = 15; i >= zrun_start + zeroes; --i) {
      addr_out->s6_addr[i] = addr_out->s6_addr[i - zeroes];
    }
    for (i = zrun_start; i < zrun_start + zeroes; ++i) {
      KASSERT_DBG(i < 16);
      addr_out->s6_addr[i] = 0;
    }
  }
  return 0;
}

int str2sin6(const char* ip, int port, struct sockaddr_in6* addr_out) {
  kmemset(addr_out, 0, sizeof(struct sockaddr_in6));
  int result = str2inet6(ip, &addr_out->sin6_addr);
  if (result) {
    return result;
  }
  addr_out->sin6_family = AF_INET6;
  addr_out->sin6_port = htob16(port);
  return 0;
}

char* sockaddr2str(const struct sockaddr* saddr, socklen_t saddr_len,
                   char* buf) {
  switch (saddr->sa_family) {
    case AF_INET:
      if (saddr_len < (socklen_t)sizeof(struct sockaddr_in)) {
        ksprintf(buf, "<bad AF_INET addr>");
      } else {
        if (ENABLE_KERNEL_SAFETY_NETS) {
          // IP address plus a colon, five digits, and a NULL.
          kmemset(buf, 0xab, INET_PRETTY_LEN + 1 + 5 + 1);
        }
        const struct sockaddr_in* sin = (const struct sockaddr_in*)saddr;
        const uint8_t* bytes = (const uint8_t*)&sin->sin_addr.s_addr;
        ksprintf(buf, "%d.%d.%d.%d:%d", bytes[0], bytes[1], bytes[2], bytes[3],
                 btoh16(sin->sin_port));
      }
      break;

    case AF_INET6:
      if (saddr_len < (socklen_t)sizeof(struct sockaddr_in6)) {
        ksprintf(buf, "<bad AF_INET6 addr>");
      } else {
        if (ENABLE_KERNEL_SAFETY_NETS) {
          // IP address plus two brackets, a colon, five digits, and a NULL.
          kmemset(buf, 0xab, INET6_PRETTY_LEN + 2 + 1 + 5 + 1);
        }
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)saddr;
        kstrcpy(buf, "[");
        inet62str(&sin6->sin6_addr, buf + 1);
        ksprintf(buf + kstrlen(buf), "]:%d", btoh16(sin6->sin6_port));
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

socklen_t sizeof_sockaddr(sa_family_t sa_family) {
  switch (sa_family) {
    case AF_UNSPEC: return sizeof(struct sockaddr);
    case AF_UNIX: return sizeof(struct sockaddr_un);
    case AF_INET: return sizeof(struct sockaddr_in);
    case AF_INET6: return sizeof(struct sockaddr_in6);
  }
  klogfm(KL_NET, DFATAL, "unknown address family: %d\n", sa_family);
  return sizeof(struct sockaddr_storage);
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

    case ADDR_INET6: {
      if (saddr_len < (int)sizeof(struct sockaddr_in6)) {
        return -EINVAL;
      }
      struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)saddr;
      addr_in6->sin6_family = AF_INET6;
      addr_in6->sin6_addr = naddr->a.ip6;
      addr_in6->sin6_port = htob16(port);
      addr_in6->sin6_flowinfo = 0;
      addr_in6->sin6_scope_id = 0;
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

    case ADDR_INET6: {
      if (saddr_len < (int)sizeof(struct sockaddr_in6)) {
        return -EINVAL;
      }
      const struct sockaddr_in6* addr_in6 = (const struct sockaddr_in6*)saddr;
      if (naddr) {
        naddr->family = ADDR_INET6;
        naddr->a.ip6 = addr_in6->sin6_addr;
      }
      if (port) {
        *port = btoh16(addr_in6->sin6_port);
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
  if (addr->sa_family == AF_INET) {
    KASSERT(addr_len >= (socklen_t)sizeof(struct sockaddr_in));
    const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
    return btoh16(sin->sin_port);
  } else if (addr->sa_family == AF_INET6) {
    KASSERT(addr_len >= (socklen_t)sizeof(struct sockaddr_in6));
    const struct sockaddr_in6* sin = (const struct sockaddr_in6*)addr;
    return btoh16(sin->sin6_port);
  } else {
    KLOG(FATAL, "Unknown sockaddr family %d\n", addr->sa_family);
    return 0;
  }
}

void set_sockaddr_port(struct sockaddr* addr, socklen_t addr_len,
                       in_port_t port) {
  if (addr->sa_family == AF_INET) {
    KASSERT(addr_len >= (socklen_t)sizeof(struct sockaddr_in));
    struct sockaddr_in* sin = (struct sockaddr_in*)addr;
    sin->sin_port = btoh16(port);
  } else if (addr->sa_family == AF_INET6) {
    KASSERT(addr_len >= (socklen_t)sizeof(struct sockaddr_in6));
    struct sockaddr_in6* sin = (struct sockaddr_in6*)addr;
    sin->sin6_port = btoh16(port);
  } else {
    KLOG(FATAL, "Unknown sockaddr family %d\n", addr->sa_family);
  }
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
  if (af == AF_INET) {
    struct sockaddr_in* in_addr = (struct sockaddr_in*)addr;
    in_addr->sin_family = AF_INET;
    in_addr->sin_addr.s_addr = INADDR_ANY;
    in_addr->sin_port = 0;
  } else if (af == AF_INET6) {
    struct sockaddr_in6* in_addr = (struct sockaddr_in6*)addr;
    kmemset(in_addr, 0, sizeof(struct sockaddr_in6));
    in_addr->sin6_family = AF_INET6;
  } else {
    KLOG(FATAL, "Unknown sockaddr family %d\n", addr->sa_family);
  }
}

bool in6_is_any(const struct in6_addr* addr) {
  for (int i = 0; i < 16; ++i) {
    if (addr->s6_addr[i] != 0) {
      return false;
    }
  }
  return true;
}

bool inet_is_anyaddr(const struct sockaddr* addr) {
  KASSERT(addr->sa_family == AF_INET || addr->sa_family == AF_UNIX ||
          addr->sa_family == AF_INET6 || addr->sa_family == AF_UNSPEC);

  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
    return sin->sin_addr.s_addr == INADDR_ANY;
  } else if (addr->sa_family == AF_INET6) {
    const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
    return in6_is_any(&sin6->sin6_addr);
  }

  return false;
}

bool netaddr_is_anyaddr(const netaddr_t* addr) {
  switch (addr->family) {
    case ADDR_INET:
      return addr->a.ip4.s_addr == INADDR_ANY;

    case ADDR_INET6:
      return in6_is_any(&addr->a.ip6);

    case ADDR_UNSPEC:
      return false;
  }
  KLOG(DFATAL, "Unknown netaddr family %d\n", addr->family);
  return false;
}

bool sockaddr_equal(const struct sockaddr* A, const struct sockaddr* B) {
  if (A->sa_family != B->sa_family) {
    return false;
  }

  switch (A->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* A4 = (const struct sockaddr_in*)A;
      const struct sockaddr_in* B4 = (const struct sockaddr_in*)B;
      return (A4->sin_addr.s_addr == B4->sin_addr.s_addr) &&
             (A4->sin_port == B4->sin_port);
    }

    case AF_INET6: {
      const struct sockaddr_in6* A6 = (const struct sockaddr_in6*)A;
      const struct sockaddr_in6* B6 = (const struct sockaddr_in6*)B;
      return (kmemcmp(&A6->sin6_addr, &B6->sin6_addr,
                      sizeof(struct in6_addr)) == 0) &&
             (A6->sin6_port == B6->sin6_port);
    }
  }
  klogfm(KL_NET, DFATAL, "unknown address family: %d\n", A->sa_family);
  return false;
}
