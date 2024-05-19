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
#include <stdint.h>

#include "common/endian.h"
#include "common/errno.h"
#include "common/kstring.h"
#include "dev/net/tuntap.h"
#include "net/addr.h"
#include "net/eth/eth.h"
#include "net/eth/ethertype.h"
#include "net/ip/checksum.h"
#include "net/ip/icmpv6/ndp.h"
#include "net/ip/icmpv6/ndp_protocol.h"
#include "net/ip/icmpv6/protocol.h"
#include "net/ip/ip6_hdr.h"
#include "net/mac.h"
#include "net/neighbor_cache_ops.h"
#include "net/pbuf.h"
#include "net/util.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define TAP_BUFSIZE 500
#define SRC_IP "2001:db8::1"
#define SRC_IP2 "2001:db8::3"

typedef struct {
  int tap_fd;
  nic_t* nic;
  char nic_mac[NIC_MAC_PRETTY_LEN];
} test_fixture_t;

// Creates a in6_addr from a test-encoded (no zero compression, etc) string.
static struct in6_addr* str2addr6(const char* s) {
  int index = 0;
  int byte = 0;
  static struct in6_addr a;
  kmemset(&a, 0, sizeof(a));
  for (; *s; ++s) {
    if (*s == ':') continue;
    if (index > 32) {
      KTEST_ADD_FAILURE("Too long string passed to str2addr6");
      break;
    }
    int digit = 0;
    if (*s >= '0' && *s <= '9') {
      digit = *s - '0';
    } else if (*s >= 'a' && *s <= 'f') {
      digit = *s - 'a' + 10;
    } else if (*s >= 'A' && *s <= 'F') {
      digit = *s - 'A' + 10;
    } else {
      KTEST_ADD_FAILURE("Invalid character passed to str2addr6");
      break;
    }
    byte = 16 * byte + digit;
    if (index % 2 == 1) {
      a.s6_addr[index / 2] = byte;
      byte = 0;
    }
    index++;
  }
  if (index < 32) {
    KTEST_ADD_FAILURE("Too short string passed to str2addr6");
  }
  return &a;
}

static void addr2str_tests(void) {
  KTEST_BEGIN("IPv6 address addr-to-string");
  char buf[INET6_PRETTY_LEN + 1];
  buf[INET6_PRETTY_LEN] = '\0';
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:db8::1",
      inet62str(str2addr6("2001:0db8:0000:0000:0000:0000:0000:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:db8::2:0:1",
      inet62str(str2addr6("2001:0db8:0000:0000:0000:0002:0000:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:db8::2:0:0:1",
      inet62str(str2addr6("2001:0db8:0000:0000:0002:0000:0000:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:db8:3:0:2::1",
      inet62str(str2addr6("2001:0db8:0003:0000:0002:0000:0000:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:db8:3:0:2::",
      inet62str(str2addr6("2001:0db8:0003:0000:0002:0000:0000:0000"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:0:0:2::1",
      inet62str(str2addr6("2001:0000:0000:0002:0000:0000:0000:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "2001:db8:0:1:1:1:1:1",
      inet62str(str2addr6("2001:0db8:0000:0001:0001:0001:0001:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "::1",
      inet62str(str2addr6("0000:0000:0000:0000:0000:0000:0000:0001"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "::",
      inet62str(str2addr6("0000:0000:0000:0000:0000:0000:0000:0000"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "1::",
      inet62str(str2addr6("0001:0000:0000:0000:0000:0000:0000:0000"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "::1:0:0:0:2",
      inet62str(str2addr6("0000:0000:0000:0001:0000:0000:0000:0002"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "0:0:1::2",
      inet62str(str2addr6("0000:0000:0001:0000:0000:0000:0000:0002"), buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  KEXPECT_STREQ(
      "::1:0:0:2:0:0",
      inet62str(str2addr6("0000:0000:0001:0000:0000:0002:0000:0000"), buf));
}

static void str2addr_tests(void) {
  KTEST_BEGIN("IPv6 address string-to-addr");
  char buf[INET6_PRETTY_LEN + 1];
  buf[INET6_PRETTY_LEN] = '\0';
  struct in6_addr addr;

  // Start with the same tests as above (round trip a canonical representation).
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:1:2:3000:bacd:1234:ffff", &addr));
  KEXPECT_STREQ("2001:db8:1:2:3000:bacd:1234:ffff", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &addr));
  KEXPECT_STREQ("2001:db8::1", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:1", &addr));
  KEXPECT_STREQ("2001:db8::2:0:1", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:0:1", &addr));
  KEXPECT_STREQ("2001:db8::2:0:0:1", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:3:0:2::1", &addr));
  KEXPECT_STREQ("2001:db8:3:0:2::1", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:3:0:2::", &addr));
  KEXPECT_STREQ("2001:db8:3:0:2::", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:0:0:2::1", &addr));
  KEXPECT_STREQ("2001:0:0:2::1", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:0:1:1:1:1:1", &addr));
  KEXPECT_STREQ("2001:db8:0:1:1:1:1:1", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::1", &addr));
  KEXPECT_STREQ("::1", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::", &addr));
  KEXPECT_STREQ("::", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("1::", &addr));
  KEXPECT_STREQ("1::", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::1:0:0:0:2", &addr));
  KEXPECT_STREQ("::1:0:0:0:2", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("0:0:1::2", &addr));
  KEXPECT_STREQ("0:0:1::2", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::1:0:0:2:0:0", &addr));
  KEXPECT_STREQ("::1:0:0:2:0:0", inet62str(&addr, buf));
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::ffff:0", &addr));
  KEXPECT_STREQ("::ffff:0", inet62str(&addr, buf));

  // Test mixing upper/lower case hex digits.
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:dB8:0:aa:B0:1:1:1", &addr));
  KEXPECT_STREQ("2001:db8:0:aa:b0:1:1:1", inet62str(&addr, buf));

  // Test extra leading zeroes.
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:0db8::001", &addr));
  KEXPECT_STREQ("2001:db8::1", inet62str(&addr, buf));

  // Test various non-canonical zeroes strings.
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:0:0:0:000::1", &addr));
  KEXPECT_STREQ("2001:db8::1", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:0:0000:0:0:0::1", &addr));
  KEXPECT_STREQ("2001:db8::1", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("2001:db8:0:0000:0:0::1", &addr));
  KEXPECT_STREQ("2001:db8::1", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("0:0000:0:0:0:00:000:1", &addr));
  KEXPECT_STREQ("::1", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::", &addr));
  KEXPECT_STREQ("::", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("0::", &addr));
  KEXPECT_STREQ("::", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::0", &addr));
  KEXPECT_STREQ("::", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("0::0", &addr));
  KEXPECT_STREQ("::", inet62str(&addr, buf));

  kmemset(buf, 'x', INET6_PRETTY_LEN);
  kmemset(&addr, 0xab, sizeof(addr));
  KEXPECT_EQ(0, str2inet6("::1:2", &addr));
  KEXPECT_STREQ("::1:2", inet62str(&addr, buf));

  // Test invalid inputs.
  KEXPECT_EQ(-EINVAL, str2inet6("::1::2", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("::1:::2", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6(":::1:2", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6(":::1", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6(":1::", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6(":1::2", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:x::", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1::x:1", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:x:2:3:4:5:6:7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:2:3:4:5:6:7:8:9", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:2:3:4:5:6:7:8:", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6(":1:2:3:4:5:6:7:8", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:2:3:4:5:6:7:", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:2:3:4:5:6:7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1::2:3::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:22222:3::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:00000:3::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:!:3::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:0xab00::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:0xba::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:10001::7", &addr));
  KEXPECT_EQ(-EINVAL, str2inet6("1:1000bacd::7", &addr));

  KTEST_BEGIN("IPv6: str2sin6() tests");
  struct sockaddr_in6 sin6;
  KEXPECT_EQ(-EINVAL, str2sin6("1:10001::7", 10, &sin6));
  KEXPECT_EQ(0, str2sin6("1::7", 0xabcd, &sin6));
  KEXPECT_EQ(AF_INET6, sin6.sin6_family);
  KEXPECT_STREQ("1::7", inet62str(&sin6.sin6_addr, buf));
  KEXPECT_EQ(btoh16(0xabcd), sin6.sin6_port);
  KEXPECT_EQ(0, sin6.sin6_flowinfo);
  KEXPECT_EQ(0, sin6.sin6_scope_id);

  KTEST_BEGIN("IPv6: sockaddr2str tests");
  KEXPECT_EQ(0, str2sin6("1::7", 1234, &sin6));
  KEXPECT_STREQ("[1::7]:1234", sockaddr2str((struct sockaddr*)&sin6,
                                            sizeof(sin6), buf));
  KEXPECT_STREQ("<bad AF_INET6 addr>",
                sockaddr2str((struct sockaddr*)&sin6, sizeof(sin6) - 1, buf));
}

static void addr_tests(void) {
  KTEST_BEGIN("IPv6 address test helpers");
  char buf[INET6_PRETTY_LEN];
  kmemset(buf, 'x', INET6_PRETTY_LEN);
  struct in6_addr addr;
  addr = *str2addr6("2001:0db8:85a3:08d3:1319:8a2e:0370:7348");
  KEXPECT_EQ(0x20, addr.s6_addr[0]);
  KEXPECT_EQ(0x01, addr.s6_addr[1]);
  KEXPECT_EQ(0x0d, addr.s6_addr[2]);
  KEXPECT_EQ(0xb8, addr.s6_addr[3]);
  KEXPECT_EQ(0x85, addr.s6_addr[4]);
  KEXPECT_EQ(0xa3, addr.s6_addr[5]);
  KEXPECT_EQ(0x08, addr.s6_addr[6]);
  KEXPECT_EQ(0xd3, addr.s6_addr[7]);
  KEXPECT_EQ(0x13, addr.s6_addr[8]);
  KEXPECT_EQ(0x19, addr.s6_addr[9]);
  KEXPECT_EQ(0x8a, addr.s6_addr[10]);
  KEXPECT_EQ(0x2e, addr.s6_addr[11]);
  KEXPECT_EQ(0x03, addr.s6_addr[12]);
  KEXPECT_EQ(0x70, addr.s6_addr[13]);
  KEXPECT_EQ(0x73, addr.s6_addr[14]);
  KEXPECT_EQ(0x48, addr.s6_addr[15]);

  addr2str_tests();
  str2addr_tests();
}

static void netaddr_tests(void) {
  KTEST_BEGIN("IPv6 netaddr tests");
  char buf[INET6_PRETTY_LEN];
  struct sockaddr_in6 sin6;
  netaddr_t na;
  KEXPECT_EQ(0, str2sin6("2001:db8::1", 100, &sin6));
  KEXPECT_EQ(-EINVAL, sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6) - 1,
                                   &na, NULL));
  KEXPECT_EQ(0, sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na, NULL));
  KEXPECT_EQ(ADDR_INET6, na.family);
  KEXPECT_STREQ("2001:db8::1", inet62str(&na.a.ip6, buf));
  int port = 0;
  KEXPECT_EQ(0,
             sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na, &port));
  KEXPECT_EQ(100, port);

  kmemset(&sin6, 0xab, sizeof(sin6));
  KEXPECT_EQ(-EINVAL, net2sockaddr(&na, 1234, &sin6, sizeof(sin6) - 1));
  KEXPECT_EQ(0, net2sockaddr(&na, 1234, &sin6, sizeof(sin6)));
  KEXPECT_STREQ("2001:db8::1", inet62str(&sin6.sin6_addr, buf));
  KEXPECT_EQ(htob16(1234), sin6.sin6_port);
  KEXPECT_EQ(AF_INET6, sin6.sin6_family);
  KEXPECT_EQ(0, sin6.sin6_flowinfo);
  KEXPECT_EQ(0, sin6.sin6_scope_id);

  netaddr_t na2;
  KEXPECT_TRUE(netaddr_eq(&na, &na));

  KEXPECT_EQ(0, str2sin6("2001:db8::2", 100, &sin6));
  KEXPECT_EQ(0,
             sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na2, NULL));
  KEXPECT_FALSE(netaddr_eq(&na, &na2));

  network_t network;
  network.addr = na2;
  network.prefix_len = 128;
  KEXPECT_TRUE(netaddr_match(&na2, &network));
  KEXPECT_FALSE(netaddr_match(&na, &network));
  network.prefix_len = 127;
  KEXPECT_TRUE(netaddr_match(&na2, &network));
  network.prefix_len = 20;
  KEXPECT_TRUE(netaddr_match(&na2, &network));

  KEXPECT_EQ(0, str2sin6("2001:da8::2", 100, &sin6));
  KEXPECT_EQ(0,
             sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na2, NULL));
  KEXPECT_FALSE(netaddr_eq(&na, &na2));
  network.prefix_len = 20;
  KEXPECT_TRUE(netaddr_match(&na2, &network));
  network.prefix_len = 32;
  KEXPECT_FALSE(netaddr_match(&na2, &network));
  network.prefix_len = 25;
  KEXPECT_TRUE(netaddr_match(&na2, &network));
  network.prefix_len = 28;
  KEXPECT_FALSE(netaddr_match(&na2, &network));
  network.prefix_len = 27;
  KEXPECT_TRUE(netaddr_match(&na2, &network));
}

static void sockaddr_tests(void) {
  KTEST_BEGIN("IPv6 sockaddr tests");
  KEXPECT_EQ(sizeof(struct sockaddr_in6), sizeof_sockaddr(AF_INET6));
  char buf[INET6_PRETTY_LEN];
  struct sockaddr_in6 sin6;
  netaddr_t na;
  KEXPECT_EQ(0, str2sin6("2001:db8::1", 100, &sin6));
  KEXPECT_EQ(100, get_sockaddr_port((struct sockaddr*)&sin6, sizeof(sin6)));
  set_sockaddr_port((struct sockaddr*)&sin6, sizeof(sin6), 1234);
  KEXPECT_STREQ("2001:db8::1", inet62str(&sin6.sin6_addr, buf));
  KEXPECT_EQ(htob16(1234), sin6.sin6_port);

  kmemset(&sin6, 0xab, sizeof(sin6));
  inet_make_anyaddr(AF_INET6, (struct sockaddr*)&sin6);
  KEXPECT_STREQ("::", inet62str(&sin6.sin6_addr, buf));

  KEXPECT_TRUE(inet_is_anyaddr((struct sockaddr*)&sin6));
  sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na, NULL);
  KEXPECT_TRUE(netaddr_is_anyaddr(&na));
  sin6.sin6_addr.s6_addr[15] = 1;
  KEXPECT_FALSE(inet_is_anyaddr((struct sockaddr*)&sin6));
  sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na, NULL);
  KEXPECT_FALSE(netaddr_is_anyaddr(&na));
  KEXPECT_EQ(0, str2sin6("2001:db8::1", 100, &sin6));
  KEXPECT_FALSE(inet_is_anyaddr((struct sockaddr*)&sin6));
  sock2netaddr((struct sockaddr*)&sin6, sizeof(sin6), &na, NULL);
  KEXPECT_FALSE(netaddr_is_anyaddr(&na));
}

static const uint8_t kTestPacket[] = {
    0x52, 0x56, 0x00, 0x00, 0x00, 0x02, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    0x86, 0xdd, 0x60, 0x0d, 0xd7, 0x86, 0x00, 0x28, 0x06, 0x40, 0xfe, 0xc0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12,
    0x34, 0x56, 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaa, 0x24, 0x15, 0xb3, 0x82, 0xdf,
    0xda, 0x78, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfd, 0x20, 0x83, 0x26,
    0x00, 0x00, 0x02, 0x04, 0x05, 0xa0, 0x04, 0x02, 0x08, 0x0a, 0x37, 0xe3,
    0xf1, 0x79, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07};

static void pkt_tests(void) {
  KTEST_BEGIN("IPv6 packet struct tests");
  const ip6_hdr_t* hdr = (const ip6_hdr_t*)(kTestPacket + sizeof(eth_hdr_t));
  KEXPECT_EQ(6, ip6_version(*hdr));
  KEXPECT_EQ(0, ip6_traffic_class(*hdr));
  KEXPECT_EQ(0xdd786, ip6_flow(*hdr));
  KEXPECT_EQ(40, btoh16(hdr->payload_len));
  KEXPECT_EQ(IPPROTO_TCP, hdr->next_hdr);
  KEXPECT_EQ(64, hdr->hop_limit);

  char buf[INET6_PRETTY_LEN];
  KEXPECT_STREQ("fec0::5054:ff:fe12:3456", inet62str(&hdr->src_addr, buf));
  KEXPECT_STREQ("fec0::2", inet62str(&hdr->dst_addr, buf));

  KTEST_BEGIN("IPv6: ip6_add_hdr() test");
  pbuf_t* pb = pbuf_create(0, INET6_HEADER_RESERVE + 10);
  kmemset(pbuf_get(pb), 0xaa, INET6_HEADER_RESERVE + 10);
  pbuf_pop_header(pb, INET6_HEADER_RESERVE);
  struct in6_addr src, dst;
  KEXPECT_EQ(0, str2inet6("fec0::5054:ff:fe12:3456", &src));
  KEXPECT_EQ(0, str2inet6("fec0::2", &dst));
  ip6_add_hdr(pb, &src, &dst, IPPROTO_TCP, 0xabcdef12);
  hdr = (const ip6_hdr_t*)pbuf_get(pb);
  KEXPECT_EQ(6, ip6_version(*hdr));
  KEXPECT_EQ(0, ip6_traffic_class(*hdr));
  KEXPECT_EQ(0xdef12, ip6_flow(*hdr));
  KEXPECT_EQ(10, btoh16(hdr->payload_len));
  KEXPECT_EQ(IPPROTO_TCP, hdr->next_hdr);
  KEXPECT_EQ(64, hdr->hop_limit);

  pbuf_free(pb);
}

static void ndp_send_request_test(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: send request");
  nbr_cache_clear(t->nic);

  struct in6_addr addr6;
  KEXPECT_EQ(0, str2inet6("2001:db8::fffe:12:3456", &addr6));

  kspin_lock(&t->nic->lock);
  ndp_send_request(t->nic, &addr6);
  kspin_unlock(&t->nic->lock);

  // First check the ethernet header.
  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t) + 8,
      vfs_read(t->tap_fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic_mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("33:33:FF:12:34:56", mac2str(eth_hdr->mac_dst, mac));

  // ...then the IPv6 header.
  const ip6_hdr_t* ip6_hdr =
      (const ip6_hdr_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(0, ip6_traffic_class(*ip6_hdr));
  KEXPECT_EQ(0, ip6_flow(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_solict_t) + 8, btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(255, ip6_hdr->hop_limit);

  KEXPECT_STREQ(SRC_IP, inet62str(&ip6_hdr->src_addr, addr));
  // The solicited-node multicast address for the requested IP.
  KEXPECT_STREQ("ff02::1:ff12:3456", inet62str(&ip6_hdr->dst_addr, addr));

  // ...then the ICMPv6 and NDP headers.
  const ndp_nbr_solict_t* pkt =
      (const ndp_nbr_solict_t*)((uint8_t*)ip6_hdr + sizeof(ip6_hdr_t));
  KEXPECT_EQ(135, pkt->hdr.type);
  KEXPECT_EQ(0, pkt->hdr.code);
  KEXPECT_EQ(0, pkt->reserved);
  KEXPECT_STREQ("2001:db8::fffe:12:3456", inet62str(&pkt->target, addr));

  // ...and finally we should include a source link-layer address option.
  const uint8_t* option = ((uint8_t*)pkt + sizeof(ndp_nbr_solict_t));
  KEXPECT_EQ(1 /* ICMPV6_OPTION_SRC_LL_ADDR */, option[0]);
  KEXPECT_EQ(1 /* 8 octets */, option[1]);
  KEXPECT_STREQ(t->nic_mac, mac2str(&option[2], mac));

  // Verify the ICMP checksum.
  ip6_pseudo_hdr_t phdr;
  kmemcpy(&phdr.src_addr, &ip6_hdr->src_addr, sizeof(struct in6_addr));
  kmemcpy(&phdr.dst_addr, &ip6_hdr->dst_addr, sizeof(struct in6_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.next_hdr = IPPROTO_ICMPV6;
  phdr.payload_len = htob32(sizeof(ndp_nbr_solict_t) + 8);
  KEXPECT_EQ(
      0, ip_checksum2(&phdr, sizeof(phdr), pkt, sizeof(ndp_nbr_solict_t) + 8));
}

static void ndp_recv_advert_test(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor advert");
  nbr_cache_clear(t->nic);

  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_advert_t), 24);
  uint8_t* options = pbuf_get(pb);

  // Put a bogus option first, then the target link layer option.
  options[0] = 100;
  options[1] = 2;  // 16 octets.
  options[16] = ICMPV6_OPTION_TGT_LL_ADDR;
  options[17] = 1;  // 8 octets.
  KEXPECT_EQ(0, str2mac("01:02:03:04:05:06", &options[18]));

  pbuf_push_header(pb, sizeof(ndp_nbr_advert_t));
  ndp_nbr_advert_t* pkt = (ndp_nbr_advert_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_ADVERT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->flags =
      htob32(NDP_NBR_ADVERT_FLAG_SOLICITED | NDP_NBR_ADVERT_FLAG_OVERRIDE);
  KEXPECT_EQ(0, str2inet6("2001:db8::fffe:12:3456", &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::fffe:12:3456", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6(SRC_IP, &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(sizeof(ndp_nbr_advert_t) + 24);
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // There shouldn't be an entry for the IP yet.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &pkt->target, sizeof(struct in6_addr));

  nbr_cache_entry_t entry;
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic, na, &entry, 0));
  // We should have sent a request packet.
  char buf[100];
  KEXPECT_LT(0, vfs_read(t->tap_fd, buf, 100));

  // Send the response.
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);

  // Now the lookup should succeed.
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(0, nbr_cache_lookup(t->nic, na, &entry, 0));
  KEXPECT_STREQ("01:02:03:04:05:06", mac2str(entry.mac.addr, buf));
}

static void ndp_recv_solicit_test_no_src_addr(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (no source LL address)");
  nbr_cache_clear(t->nic);

  // Pre-seed the neighbor cache with the sender's address.  Use yet another
  // MAC address to ensure this one is used, and not the one in the request
  // packet (or source option).
  netaddr_t entry_addr;
  entry_addr.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &entry_addr.a.ip6));
  nic_mac_t entry_mac;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", entry_mac.addr));
  nbr_cache_insert(t->nic, entry_addr, entry_mac.addr);

  // N.B. this request is not RFC-compliant, as it does not include the source
  // link-layer address option even though this is a multicast solicit.
  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(sizeof(ndp_nbr_solict_t));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet.
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->tap_fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic_mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("00:00:00:00:00:05", mac2str(eth_hdr->mac_dst, mac));

  const ip6_hdr_t* ip6_hdr = (const ip6_hdr_t*)&buf[idx];
  idx += sizeof(ip6_hdr_t);
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(0, ip6_flow(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_advert_t) + 8, btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_STREQ(SRC_IP, inet62str(&ip6_hdr->src_addr, addr));
  KEXPECT_STREQ("2001:db8::10", inet62str(&ip6_hdr->dst_addr, addr));

  const ndp_nbr_advert_t* advert = (const ndp_nbr_advert_t*)&buf[idx];
  idx += sizeof(ndp_nbr_advert_t);
  KEXPECT_EQ(ICMPV6_NDP_NBR_ADVERT, advert->hdr.type);
  KEXPECT_EQ(0, advert->hdr.code);
  KEXPECT_NE(0, advert->hdr.checksum);
  KEXPECT_EQ(NDP_NBR_ADVERT_FLAG_SOLICITED | NDP_NBR_ADVERT_FLAG_OVERRIDE,
             btoh32(advert->flags));
  KEXPECT_STREQ(SRC_IP, inet62str(&advert->target, addr));

  const uint8_t* option = (const uint8_t*)&buf[idx];
  KEXPECT_EQ(ICMPV6_OPTION_TGT_LL_ADDR, option[0]);
  KEXPECT_EQ(1, option[1]);
  KEXPECT_STREQ(t->nic_mac, mac2str(&option[2], mac));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void ndp_recv_solicit_test_unknown_neighbor(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit "
              "(no source LL address, and neighbor is unknown)");
  nbr_cache_clear(t->nic);

  // N.B. this request is not RFC-compliant, as it does not include the source
  // link-layer address option even though this is a multicast solicit.
  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(sizeof(ndp_nbr_solict_t));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should get a NDP solicit for ourselves.
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t) + 8,
      vfs_read(t->tap_fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic_mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("33:33:FF:00:00:10", mac2str(eth_hdr->mac_dst, mac));

  const ip6_hdr_t* ip6_hdr = (const ip6_hdr_t*)&buf[idx];
  idx += sizeof(ip6_hdr_t);
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(0, ip6_flow(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_solict_t) + 8, btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_STREQ(SRC_IP, inet62str(&ip6_hdr->src_addr, addr));
  KEXPECT_STREQ("ff02::1:ff00:10", inet62str(&ip6_hdr->dst_addr, addr));

  // ...then the ICMPv6 and NDP headers.
  const ndp_nbr_solict_t* resp =
      (const ndp_nbr_solict_t*)((uint8_t*)ip6_hdr + sizeof(ip6_hdr_t));
  KEXPECT_EQ(135, resp->hdr.type);
  KEXPECT_EQ(0, resp->hdr.code);
  KEXPECT_EQ(0, resp->reserved);
  KEXPECT_STREQ("2001:db8::10", inet62str(&resp->target, addr));

  // ...and finally we should include a source link-layer address option.
  const uint8_t* option = ((uint8_t*)resp + sizeof(ndp_nbr_solict_t));
  KEXPECT_EQ(1 /* ICMPV6_OPTION_SRC_LL_ADDR */, option[0]);
  KEXPECT_EQ(1 /* 8 octets */, option[1]);
  KEXPECT_STREQ(t->nic_mac, mac2str(&option[2], mac));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void ndp_recv_solicit_test(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit");
  nbr_cache_clear(t->nic);

  pbuf_t* pb =
      pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_solict_t), 4 * 8);
  // Start with the options.  Do two bogus ones and a source link-layer addr.
  uint8_t* option = (uint8_t*)pbuf_get(pb);
  option[0] = 12;  // Bogus #1.
  option[1] = 2;
  option += 2 * 8;
  option[0] = 1;  // Link-layer source option.
  option[1] = 1;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", &option[2]));
  option += 8;
  option[0] = 19;  // Bogus #2.
  option[1] = 1;

  pbuf_push_header(pb, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(pbuf_size(pb));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet.
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->tap_fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic_mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("00:00:00:00:00:05", mac2str(eth_hdr->mac_dst, mac));

  const ip6_hdr_t* ip6_hdr = (const ip6_hdr_t*)&buf[idx];
  idx += sizeof(ip6_hdr_t);
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(0, ip6_flow(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_advert_t) + 8, btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_STREQ(SRC_IP, inet62str(&ip6_hdr->src_addr, addr));
  KEXPECT_STREQ("2001:db8::10", inet62str(&ip6_hdr->dst_addr, addr));

  const ndp_nbr_advert_t* advert = (const ndp_nbr_advert_t*)&buf[idx];
  idx += sizeof(ndp_nbr_advert_t);
  KEXPECT_EQ(ICMPV6_NDP_NBR_ADVERT, advert->hdr.type);
  KEXPECT_EQ(0, advert->hdr.code);
  KEXPECT_NE(0, advert->hdr.checksum);
  KEXPECT_EQ(NDP_NBR_ADVERT_FLAG_SOLICITED | NDP_NBR_ADVERT_FLAG_OVERRIDE,
             btoh32(advert->flags));
  KEXPECT_STREQ(SRC_IP, inet62str(&advert->target, addr));

  option = (uint8_t*)&buf[idx];
  KEXPECT_EQ(ICMPV6_OPTION_TGT_LL_ADDR, option[0]);
  KEXPECT_EQ(1, option[1]);
  KEXPECT_STREQ(t->nic_mac, mac2str(&option[2], mac));

  // We should have also seeded the neighbor cache with the src LL option.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(0, nbr_cache_lookup(t->nic, na, &entry, 0));
  KEXPECT_STREQ("00:00:00:00:00:05", mac2str(entry.mac.addr, buf));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option)");
  nbr_cache_clear(t->nic);

  pbuf_t* pb =
      pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_solict_t), 4 * 8);
  // Start with the options.  Do two bogus ones and a source link-layer addr.
  uint8_t* option = (uint8_t*)pbuf_get(pb);
  option[0] = 12;  // Bogus #1.
  option[1] = 0;  // Too-short option.
  option += 2 * 8;
  option[0] = 1;  // Link-layer source option.
  option[1] = 1;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", &option[2]));
  option += 8;
  option[0] = 19;  // Bogus #2.
  option[1] = 1;

  pbuf_push_header(pb, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(pbuf_size(pb));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt2(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option 2)");
  nbr_cache_clear(t->nic);

  pbuf_t* pb =
      pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_solict_t), 3 * 8);
  // Start with the options.
  uint8_t* option = (uint8_t*)pbuf_get(pb);
  option[0] = 12;  // Bogus #1.
  option[1] = 4;  // Too-long option.
  option += 8;
  option[0] = 1;  // Link-layer source option.  Shouldn't be read.
  option[1] = 1;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", &option[2]));
  option += 8;
  option[0] = 13;  // This is past the end of the packet!
  option[1] = 1;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", &option[2]));

  pbuf_push_header(pb, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(pbuf_size(pb));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.  Omit the last 8 bytes to test if the check skips
  // processing that (otherwise valid) option data.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt3(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option 3)");
  nbr_cache_clear(t->nic);

  pbuf_t* pb =
      pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_solict_t), 4 * 8);
  // Start with the options.  Do two bogus ones and a source link-layer addr.
  uint8_t* option = (uint8_t*)pbuf_get(pb);
  option[0] = 12;  // Bogus #1.
  option[1] = 1;
  option += 2 * 8;
  option[0] = 1;  // Link-layer source option.
  option[1] = 1;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", &option[2]));
  option += 8;
  option[0] = 19;  // Bogus #2.
  option[1] = 1;  // Too-long last option.

  pbuf_push_header(pb, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(pbuf_size(pb));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt4(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option 4)");
  nbr_cache_clear(t->nic);

  pbuf_t* pb =
      pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_solict_t), 4 * 8);
  // Start with the options.  Do two bogus ones and a source link-layer addr.
  uint8_t* option = (uint8_t*)pbuf_get(pb);
  option[0] = 12;  // Bogus #1.
  option[1] = 1;
  option += 2 * 8;
  option[0] = 1;  // Link-layer source option.
  option[1] = 2;  // Bad size for LL src option.
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", &option[2]));

  pbuf_push_header(pb, sizeof(ndp_nbr_solict_t));
  ndp_nbr_solict_t* pkt = (ndp_nbr_solict_t*)pbuf_get(pb);
  pkt->hdr.type = ICMPV6_NDP_NBR_SOLICIT;
  pkt->hdr.code = 0;
  pkt->hdr.checksum = 0;
  pkt->reserved = 12345;  // Should be ignored.
  KEXPECT_EQ(0, str2inet6(SRC_IP, &pkt->target));

  ip6_pseudo_hdr_t phdr;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1:ff00:1", &phdr.dst_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.payload_len = htob16(pbuf_size(pb));
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb));

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0d:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->tap_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->tap_fd, buf, 100));
}

// TODO(ipv6): more NDP tests:
//  - match second IP
//  - doesn't match IP
//  - matches non-enabled IPs (disabled and tentative)
//  - source address is unspecified (reply to multicast)
//  - invalid option sizes (small and large, known and unknown options,
//    mismatched sizes)

static void ndp_tests(test_fixture_t* t) {
  ndp_send_request_test(t);
  ndp_recv_advert_test(t);
  ndp_recv_solicit_test_no_src_addr(t);
  ndp_recv_solicit_test_unknown_neighbor(t);
  ndp_recv_solicit_test(t);
  ndp_recv_solicit_test_bad_opt(t);
  ndp_recv_solicit_test_bad_opt2(t);
  ndp_recv_solicit_test_bad_opt3(t);
  ndp_recv_solicit_test_bad_opt4(t);
}

// TODO(ipv6): additional tests:
//  - invalid IPv6 packets
//  - invalid NDP packets (including options)
//  - too-short ipv6 and icmp and NDP packets.

void ipv6_test(void) {
  KTEST_SUITE_BEGIN("IPv6");
  KTEST_BEGIN("IPv6: test setup");
  test_fixture_t fixture;
  apos_dev_t id;
  nic_t* nic = tuntap_create(TAP_BUFSIZE, TUNTAP_TAP_MODE, &id);
  KEXPECT_NE(NULL, nic);
  fixture.nic = nic;
  mac2str(nic->mac.addr, fixture.nic_mac);

  kspin_lock(&nic->lock);
  nic->addrs[0].a.addr.family = ADDR_INET6;
  KEXPECT_EQ(0, str2inet6(SRC_IP, &nic->addrs[0].a.addr.a.ip6));
  nic->addrs[0].a.prefix_len = 64;
  nic->addrs[0].state = NIC_ADDR_ENABLED;
  nic->addrs[1].a.addr.family = ADDR_INET6;
  KEXPECT_EQ(0, str2inet6(SRC_IP2, &nic->addrs[1].a.addr.a.ip6));
  nic->addrs[1].a.prefix_len = 64;
  nic->addrs[1].state = NIC_ADDR_ENABLED;
  kspin_unlock(&nic->lock);

  KEXPECT_EQ(0, vfs_mknod("_tap_test_dev", VFS_S_IFCHR | VFS_S_IRWXU, id));
  fixture.tap_fd = vfs_open("_tap_test_dev", VFS_O_RDWR);
  KEXPECT_GE(fixture.tap_fd, 0);
  vfs_make_nonblock(fixture.tap_fd);

  // Run the tests.
  addr_tests();
  netaddr_tests();
  sockaddr_tests();
  pkt_tests();
  ndp_tests(&fixture);

  KTEST_BEGIN("IPv6: test teardown");
  KEXPECT_EQ(0, vfs_close(fixture.tap_fd));
  KEXPECT_EQ(0, vfs_unlink("_tap_test_dev"));
  KEXPECT_EQ(0, tuntap_destroy(id));
}
