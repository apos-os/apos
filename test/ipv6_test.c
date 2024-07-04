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
#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "dev/net/tuntap.h"
#include "net/addr.h"
#include "net/eth/eth.h"
#include "net/eth/ethertype.h"
#include "net/ip/checksum.h"
#include "net/ip/icmpv6/multicast.h"
#include "net/ip/icmpv6/ndp.h"
#include "net/ip/icmpv6/ndp_protocol.h"
#include "net/ip/icmpv6/protocol.h"
#include "net/ip/ip6.h"
#include "net/ip/ip6_addr.h"
#include "net/ip/ip6_hdr.h"
#include "net/ip/ip6_multicast.h"
#include "net/ip/route.h"
#include "net/ip/util.h"
#include "net/mac.h"
#include "net/neighbor_cache_ops.h"
#include "net/pbuf.h"
#include "net/test_util.h"
#include "net/util.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "test/test_nic.h"
#include "test/test_point.h"
#include "user/include/apos/net/socket/inet.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define TAP_BUFSIZE 500
#define SRC_IP "2001:db8::1"
#define SRC_IP2 "2001:db8::3"
#define DISABLED_SRC_IP "2001:db8::11"
#define DISABLED_SRC_IP2 "2001:db8::12"
#define MLD_QUERY_SRC "fe80::1234"

typedef struct {
  test_ttap_t nic;
  test_ttap_t nic2;
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

static void addr_prefix_tests(void) {
  KTEST_BEGIN("ip6_common_prefix() tests");
  struct in6_addr addr1, addr2;

  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:1", &addr1));
  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:1", &addr2));
  KEXPECT_EQ(128, ip6_common_prefix(&addr1, &addr2));

  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:0", &addr2));
  KEXPECT_EQ(127, ip6_common_prefix(&addr1, &addr2));

  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:2", &addr2));
  KEXPECT_EQ(126, ip6_common_prefix(&addr1, &addr2));

  KEXPECT_EQ(0, str2inet6("2001:db8::2:0:3", &addr2));
  KEXPECT_EQ(126, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(126, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2001:db8::", &addr2));
  KEXPECT_EQ(94, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(94, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2001:db8::2:8000:0", &addr2));
  KEXPECT_EQ(96, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(96, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2001:db8::2:1000:0", &addr2));
  KEXPECT_EQ(99, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(99, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2001:db8::3:1000:0", &addr2));
  KEXPECT_EQ(95, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(95, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("f001:db8::3:1000:0", &addr2));
  KEXPECT_EQ(0, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(0, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("7001:db8::3:1000:0", &addr2));
  KEXPECT_EQ(1, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(1, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2001::", &addr2));
  KEXPECT_EQ(20, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(20, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2001:8000::", &addr2));
  KEXPECT_EQ(16, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(16, ip6_common_prefix(&addr2, &addr1));

  KEXPECT_EQ(0, str2inet6("2000::", &addr2));
  KEXPECT_EQ(15, ip6_common_prefix(&addr1, &addr2));
  KEXPECT_EQ(15, ip6_common_prefix(&addr2, &addr1));
}

static void addr_equal_tests(void) {
  KTEST_BEGIN("sockaddr_equal() for IPv6");
  struct sockaddr_in6 addr1, addr2;
  kmemset(&addr1, 0xab, sizeof(addr1));
  kmemset(&addr2, 0xcd, sizeof(addr2));
  str2inet6("2001:db8::1", &addr1.sin6_addr);
  str2inet6("2001:db8::1", &addr2.sin6_addr);
  addr1.sin6_family = addr2.sin6_family = AF_INET6;
  addr1.sin6_port = 1000;
  addr2.sin6_port = 1000;
  addr1.sin6_scope_id = 0;
  addr2.sin6_scope_id = 0;
  addr1.sin6_flowinfo = 123;
  addr2.sin6_flowinfo = 456;
  KEXPECT_TRUE(
      sockaddr_equal((struct sockaddr*)&addr1, (struct sockaddr*)&addr2));

  addr1.sin6_port = 1001;
  KEXPECT_FALSE(
      sockaddr_equal((struct sockaddr*)&addr1, (struct sockaddr*)&addr2));
  addr1.sin6_port = addr2.sin6_port;

  addr1.sin6_addr.s6_addr[0] = 100;
  KEXPECT_FALSE(
      sockaddr_equal((struct sockaddr*)&addr1, (struct sockaddr*)&addr2));
  addr1.sin6_addr = addr2.sin6_addr;

  addr1.sin6_addr.s6_addr[10] = 100;
  KEXPECT_FALSE(
      sockaddr_equal((struct sockaddr*)&addr1, (struct sockaddr*)&addr2));
  addr1.sin6_addr = addr2.sin6_addr;

  addr1.sin6_scope_id = 1;
  addr2.sin6_scope_id = 1;
  KEXPECT_TRUE(
      sockaddr_equal((struct sockaddr*)&addr1, (struct sockaddr*)&addr2));
  addr2.sin6_scope_id = 2;
  KEXPECT_TRUE(
      sockaddr_equal((struct sockaddr*)&addr1, (struct sockaddr*)&addr2));
  addr1.sin6_scope_id = addr2.sin6_scope_id;
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

  KTEST_BEGIN("ip6_is_link_local() test");
  KEXPECT_EQ(0, str2inet6("fe80::", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("fe80::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("fe81::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("fe8f::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("fe9f::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("feaf::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("fea0::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("feb0::1", &addr));
  KEXPECT_TRUE(ip6_is_link_local(&addr));

  KEXPECT_EQ(0, str2inet6("fec0::0", &addr));
  KEXPECT_FALSE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("ff80::0", &addr));
  KEXPECT_FALSE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("fd80::0", &addr));
  KEXPECT_FALSE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("de80::0", &addr));
  KEXPECT_FALSE(ip6_is_link_local(&addr));
  KEXPECT_EQ(0, str2inet6("0e80::0", &addr));
  KEXPECT_FALSE(ip6_is_link_local(&addr));

  addr2str_tests();
  str2addr_tests();
  addr_prefix_tests();
  addr_equal_tests();
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
  nbr_cache_clear(t->nic.n);

  struct in6_addr addr6;
  KEXPECT_EQ(0, str2inet6("2001:db8::fffe:12:3456", &addr6));

  kspin_lock(&t->nic.n->lock);
  ndp_send_request(t->nic.n, &addr6, false);
  kspin_unlock(&t->nic.n->lock);

  // First check the ethernet header.
  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t) + 8,
      vfs_read(t->nic.fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
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
  KEXPECT_STREQ(t->nic.mac, mac2str(&option[2], mac));

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

static void ndp_send_request_any_addr_test(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: send request (from any-addr)");
  nbr_cache_clear(t->nic.n);

  struct in6_addr addr6;
  KEXPECT_EQ(0, str2inet6("2001:db8::fffe:12:3456", &addr6));

  kspin_lock(&t->nic.n->lock);
  ndp_send_request(t->nic.n, &addr6, true);
  kspin_unlock(&t->nic.n->lock);

  // First check the ethernet header.
  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t),
      vfs_read(t->nic.fd, buf, 100));
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf;
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("33:33:FF:12:34:56", mac2str(eth_hdr->mac_dst, mac));

  // ...then the IPv6 header.
  const ip6_hdr_t* ip6_hdr =
      (const ip6_hdr_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(0, ip6_traffic_class(*ip6_hdr));
  KEXPECT_EQ(0, ip6_flow(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_solict_t), btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(255, ip6_hdr->hop_limit);

  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, addr));
  // The solicited-node multicast address for the requested IP.
  KEXPECT_STREQ("ff02::1:ff12:3456", inet62str(&ip6_hdr->dst_addr, addr));

  // ...then the ICMPv6 and NDP headers.
  const ndp_nbr_solict_t* pkt =
      (const ndp_nbr_solict_t*)((uint8_t*)ip6_hdr + sizeof(ip6_hdr_t));
  KEXPECT_EQ(135, pkt->hdr.type);
  KEXPECT_EQ(0, pkt->hdr.code);
  KEXPECT_EQ(0, pkt->reserved);
  KEXPECT_STREQ("2001:db8::fffe:12:3456", inet62str(&pkt->target, addr));

  // Verify the ICMP checksum.
  ip6_pseudo_hdr_t phdr;
  kmemcpy(&phdr.src_addr, &ip6_hdr->src_addr, sizeof(struct in6_addr));
  kmemcpy(&phdr.dst_addr, &ip6_hdr->dst_addr, sizeof(struct in6_addr));
  kmemset(&phdr._zeroes, 0, 3);
  phdr.next_hdr = IPPROTO_ICMPV6;
  phdr.payload_len = htob32(sizeof(ndp_nbr_solict_t));
  KEXPECT_EQ(
      0, ip_checksum2(&phdr, sizeof(phdr), pkt, sizeof(ndp_nbr_solict_t)));
}

static void ndp_recv_advert_test(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor advert");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // There shouldn't be an entry for the IP yet.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &pkt->target, sizeof(struct in6_addr));

  nbr_cache_entry_t entry;
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));
  // We should have sent a request packet.
  char buf[100];
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));

  // Send the response.
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);

  // Now the lookup should succeed.
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(0, nbr_cache_lookup(t->nic.n, na, &entry, 0));
  KEXPECT_STREQ("01:02:03:04:05:06", mac2str(entry.mac.addr, buf));
}

static void ndp_recv_solicit_test_no_src_addr(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (no source LL address)");
  nbr_cache_clear(t->nic.n);

  // Pre-seed the neighbor cache with the sender's address.  Use yet another
  // MAC address to ensure this one is used, and not the one in the request
  // packet (or source option).
  netaddr_t entry_addr;
  entry_addr.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &entry_addr.a.ip6));
  nic_mac_t entry_mac;
  KEXPECT_EQ(0, str2mac("00:00:00:00:00:05", entry_mac.addr));
  nbr_cache_insert(t->nic.n, entry_addr, entry_mac.addr);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet.
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->nic.fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
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
  KEXPECT_STREQ(t->nic.mac, mac2str(&option[2], mac));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_unknown_neighbor(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit "
              "(no source LL address, and neighbor is unknown)");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should get a NDP solicit for ourselves.
  char buf[100];
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t) + 8,
      vfs_read(t->nic.fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
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
  KEXPECT_STREQ(t->nic.mac, mac2str(&option[2], mac));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet.
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->nic.fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
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
  KEXPECT_STREQ(t->nic.mac, mac2str(&option[2], mac));

  // We should have also seeded the neighbor cache with the src LL option.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(0, nbr_cache_lookup(t->nic.n, na, &entry, 0));
  KEXPECT_STREQ("00:00:00:00:00:05", mac2str(entry.mac.addr, buf));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option)");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt2(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option 2)");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.  Omit the last 8 bytes to test if the check skips
  // processing that (otherwise valid) option data.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt3(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option 3)");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_bad_opt4(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (bad option 4)");
  nbr_cache_clear(t->nic.n);

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // Packet should be ignored due to the bad option.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test2(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (second IP)");
  nbr_cache_clear(t->nic.n);

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
  KEXPECT_EQ(0, str2inet6(SRC_IP2, &pkt->target));

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet.
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->nic.fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
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
  KEXPECT_STREQ(SRC_IP2, inet62str(&advert->target, addr));

  option = (uint8_t*)&buf[idx];
  KEXPECT_EQ(ICMPV6_OPTION_TGT_LL_ADDR, option[0]);
  KEXPECT_EQ(1, option[1]);
  KEXPECT_STREQ(t->nic.mac, mac2str(&option[2], mac));

  // We should have also seeded the neighbor cache with the src LL option.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(0, nbr_cache_lookup(t->nic.n, na, &entry, 0));
  KEXPECT_STREQ("00:00:00:00:00:05", mac2str(entry.mac.addr, buf));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_no_match(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (non matching IP)");
  nbr_cache_clear(t->nic.n);

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
  KEXPECT_EQ(0, str2inet6("2008:db8::5", &pkt->target));

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have ignored the request.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));

  // We should NOT have added it to the neighbor cache.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));

  // Drain the request sent by the lookup.
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_disabled(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (disabled IP)");
  nbr_cache_clear(t->nic.n);

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
  KEXPECT_EQ(0, str2inet6(DISABLED_SRC_IP, &pkt->target));

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have ignored the request.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));

  // We should NOT have added it to the neighbor cache.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));

  // Drain the request sent by the lookup.
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_disabled2(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (disabled IP #2)");
  nbr_cache_clear(t->nic.n);

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
  KEXPECT_EQ(0, str2inet6(DISABLED_SRC_IP2, &pkt->target));

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have ignored the request.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));

  // We should NOT have added it to the neighbor cache.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));

  // Drain the request sent by the lookup.
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_ipv4(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (~match IPv4)");
  nbr_cache_clear(t->nic.n);

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
  KEXPECT_EQ(0, str2inet6("0102:0304::", &pkt->target));

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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have ignored the request.
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));

  // We should NOT have added it to the neighbor cache.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));

  // Drain the request sent by the lookup.
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_from_unspecified(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (unspecified source)");
  nbr_cache_clear(t->nic.n);

  // Incorrectly include a source link-layer option, which must be ignored
  // (alternatively, the entire packet could be dropped).
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
  KEXPECT_EQ(0, str2inet6("::", &phdr.src_addr));
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
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet to the all-nodes multicast address.
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->nic.fd, buf, 100));

  char mac[NIC_MAC_PRETTY_LEN];
  char addr[INET6_PRETTY_LEN];
  size_t idx = 0;
  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)&buf[idx];
  idx += sizeof(eth_hdr_t);
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("33:33:00:00:00:01", mac2str(eth_hdr->mac_dst, mac));

  const ip6_hdr_t* ip6_hdr = (const ip6_hdr_t*)&buf[idx];
  idx += sizeof(ip6_hdr_t);
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(0, ip6_flow(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_advert_t) + 8, btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_STREQ(SRC_IP, inet62str(&ip6_hdr->src_addr, addr));
  KEXPECT_STREQ("ff02::1", inet62str(&ip6_hdr->dst_addr, addr));

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
  KEXPECT_STREQ(t->nic.mac, mac2str(&option[2], mac));

  // We should not have added anything to the neighbor cache.
  netaddr_t na;
  na.family = AF_INET6;
  kmemcpy(&na.a.ip6, &phdr.src_addr, sizeof(struct in6_addr));
  nbr_cache_entry_t entry;
  kmemset(&entry, 0, sizeof(entry));
  KEXPECT_EQ(-EAGAIN, nbr_cache_lookup(t->nic.n, na, &entry, 0));

  // Drain the request that was sent.
  // TODO(ipv6): we should not send an NDP request for this IP.
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_recv_solicit_test_extra_ip_bytes(test_fixture_t* t) {
  KTEST_BEGIN("ICMPv6 NDP: receive neighbor solicit (extra IP bytes at end)");
  nbr_cache_clear(t->nic.n);

  pbuf_t* pb =
      pbuf_create(INET6_HEADER_RESERVE + sizeof(ndp_nbr_solict_t), 4 * 8 + 3);
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

  // Put 3 bytes of garbage at the end.
  option += 8;
  option[0] = 0x12;
  option[1] = 0x23;
  option[2] = 0x45;

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
  phdr.payload_len = htob16(pbuf_size(pb) - 3);
  phdr.next_hdr = IPPROTO_ICMPV6;
  pkt->hdr.checksum =
      ip_checksum2(&phdr, sizeof(phdr), pbuf_getc(pb), pbuf_size(pb) - 3);

  // Add the IPv6 and ethernet headers.
  ip6_add_hdr(pb, &phdr.src_addr, &phdr.dst_addr, IPPROTO_ICMPV6, 0);
  ip6_hdr_t* ip6_hdr = (ip6_hdr_t*)pbuf_get(pb);
  ip6_hdr->payload_len = htob16(btoh16(ip6_hdr->payload_len) - 3);
  nic_mac_t mac1, mac2;
  // Use different addresses for the packet itself.  These _should_ be the
  // multicast address, but the code shouldn't care.
  str2mac("07:08:09:0a:0b:0c", mac1.addr);
  str2mac("0e:0e:0f:10:11:12", mac2.addr);
  eth_add_hdr(pb, &mac2, &mac1, ET_IPV6);

  // Send the solicit.
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(pbuf_size(pb), vfs_write(t->nic.fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);
  pb = NULL;

  // We should have sent a reply packet.
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_advert_t) + 8,
      vfs_read(t->nic.fd, buf, 100));

  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
}

static void ndp_tests(test_fixture_t* t) {
  ndp_send_request_test(t);
  ndp_send_request_any_addr_test(t);
  ndp_recv_advert_test(t);
  ndp_recv_solicit_test_no_src_addr(t);
  ndp_recv_solicit_test_unknown_neighbor(t);
  ndp_recv_solicit_test(t);
  ndp_recv_solicit_test_bad_opt(t);
  ndp_recv_solicit_test_bad_opt2(t);
  ndp_recv_solicit_test_bad_opt3(t);
  ndp_recv_solicit_test_bad_opt4(t);
  ndp_recv_solicit_test2(t);
  ndp_recv_solicit_test_no_match(t);
  ndp_recv_solicit_test_disabled(t);
  ndp_recv_solicit_test_disabled2(t);
  ndp_recv_solicit_test_ipv4(t);
  ndp_recv_solicit_test_from_unspecified(t);
  ndp_recv_solicit_test_extra_ip_bytes(t);
}

static int do_cmp(test_fixture_t* t, const char* Astr, const char* Bstr,
                  const char* dst_str) {
  netaddr_t dst;
  dst.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6(dst_str, &dst.a.ip6));

  nic_addr_t A, B;
  A.state = B.state = NIC_ADDR_ENABLED;
  A.a.addr.family = B.a.addr.family = AF_INET6;
  A.a.prefix_len = B.a.prefix_len = 64;  // Unused.
  KEXPECT_EQ(0, str2inet6(Astr, &A.a.addr.a.ip6));
  KEXPECT_EQ(0, str2inet6(Bstr, &B.a.addr.a.ip6));
  int result = ip6_src_addr_cmp(&A, &B, &dst, t->nic.n);
  int result_reverse = ip6_src_addr_cmp(&B, &A, &dst, t->nic.n);
  KEXPECT_EQ(-result, result_reverse);
  if (result != -result_reverse) {
    return 5;
  }
  return result;
}

static void addr_selection_tests(test_fixture_t* t) {
  KTEST_BEGIN("ip6_src_addr_cmp(): rule 1 (prefer same address)");
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::1", "2001:db8::1"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::1", "2001:db8::2"));
  KEXPECT_EQ(-1, do_cmp(t, "2001:db8::1", "2001:db8::2", "2001:db8::2"));
  KEXPECT_EQ( 1, do_cmp(t, "2001:db8::2", "2001:db8::1", "2001:db8::2"));

  KTEST_BEGIN("ip6_src_addr_cmp(): rule 2 (prefer appropriate scope)");
  // These are the values for scope of A/B/dest we need to test --- assuming
  // do_cmp reverse A and B, these will represent all possible orderings.
  // SA   SB    D

  // 1    2     2
  KEXPECT_EQ(-1, do_cmp(t, "fe80::1", "2001:db8::1", "2001:db8::2"));
  KEXPECT_EQ(-1, do_cmp(t, "fe80::1", "2001:db8::1", "ff0e::3"));

  // 1    2     1
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::1", "fe80::3"));
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::1", "ff02::3"));
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::1", "ff12::3"));
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::1", "fff2::3"));
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::1", "ff02:1::3"));

  // 1    1     1
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1:1", "fe80::1:2", "fe80::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "ff02::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "feb0::1", "fe80::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fec0::1", "fec0::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fec8::1", "fec8::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "feb8::1", "fe80::2", "ff0e::3"));

  // 1    1     2
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "2001:db8::2"));
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "ff03::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "ff04::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "ff05::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "ff08::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe80::1", "fe80::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe88::1", "fe80::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "fe8f::1", "fe80::2", "ff0e::3"));
  KEXPECT_EQ( 0, do_cmp(t, "febf::1", "fe80::2", "ff0e::3"));

  // 2    2     1
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "fe80::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff01::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff02::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff03::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff04::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff05::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::1", "2001:db8::2", "ff08::3"));

  // 1    3     2
  KEXPECT_EQ(-1, do_cmp(t, "fe80::1", "2001:db8::2", "ff03::3"));
  KEXPECT_EQ(-1, do_cmp(t, "fe80::1", "2001:db8::2", "ff04::3"));
  KEXPECT_EQ(-1, do_cmp(t, "fe80::1", "2001:db8::2", "ff05::3"));
  KEXPECT_EQ(-1, do_cmp(t, "fe80::1", "2001:db8::2", "ff08::3"));

  // 2 (link-local)    3 (global)     1 (interface-local)
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::2", "ff01::3"));
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::2", "ff11::3"));
  KEXPECT_EQ( 1, do_cmp(t, "fe80::1", "2001:db8::2", "fff1::3"));

  // Note: this last ordering is untestable, as we don't implement the
  // deprecated unicast site-local address handling, and multicast addresses
  // can't be sources:
  // 1    2     3

  KTEST_BEGIN("ip6_src_addr_cmp(): rule 6 (match labels)");
  KEXPECT_EQ( 1, do_cmp(t, "::ffff:0:1", "2001:db8::1", "::ffff:0:3"));
  KEXPECT_EQ(-1, do_cmp(t, "::ffff:0:1", "2001:db8::1", "1::ffff:0:3"));
  KEXPECT_EQ( 0, do_cmp(t, "::ffff:1:1", "::ffff:1:2", "::ffff:0:3"));
  KEXPECT_EQ( 0, do_cmp(t, "2002::1", "2001::1", "::0:3"));
  KEXPECT_EQ( 1, do_cmp(t, "::1:1", "2001:db8::1", "::0:3"));
  KEXPECT_EQ( 0, do_cmp(t, "::2:1", "::3:2", "::0:3"));


  KTEST_BEGIN("ip6_src_addr_cmp(): rule 8 (longest matching prefix)");
  KEXPECT_EQ( 1, do_cmp(t, "2001:db8::0:1", "2001:db8::1:2", "2001:db8::3"));
  KEXPECT_EQ( 0, do_cmp(t, "2001:db8::0:2", "2001:db8::0:3", "2001:db8::"));
}

static void remove_ipv6_hook(const char* name, int count, void* arg) {
  nic_t* nic = (nic_t*)arg;
  kspin_lock(&nic->lock);
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].a.addr.family == AF_INET6) {
      nic->addrs[i].state = NIC_ADDR_NONE;
    }
  }
  kspin_unlock(&nic->lock);
}

static void pick_src_ip_tests(test_fixture_t* t) {
  KTEST_BEGIN("ip_pick_src(): IPv6 (no route)");
  netaddr_t orig_default_nexthop;
  char orig_default_nic[NIC_MAX_NAME_LEN];
  ip_get_default_route(ADDR_INET6, &orig_default_nexthop, orig_default_nic);

  struct sockaddr_in6 dst;
  kmemset(&dst, 0xcd, sizeof(dst));
  dst.sin6_family = AF_INET6;
  KEXPECT_EQ(0, str2sin6("2607:f8b0:4006:821::2004", 100, &dst));

  struct sockaddr_storage result;
  netaddr_t nexthop;
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(ADDR_INET6, nexthop, "");
  KEXPECT_EQ(-ENETUNREACH,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));


  KTEST_BEGIN("ip_pick_src(): IPv6");
  char addr[INET6_PRETTY_LEN];
  nexthop.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6("2001:db8::100", &nexthop.a.ip6));
  ip_set_default_route(ADDR_INET6, nexthop, t->nic2.n->name);

  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(0,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(AF_INET6, result.sa_family);
  KEXPECT_STREQ(SRC_IP,
                inet62str(&((struct sockaddr_in6*)&result)->sin6_addr, addr));

  KEXPECT_EQ(0, str2sin6("fe80::2", 100, &dst));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(0,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(AF_INET6, result.sa_family);
  KEXPECT_STREQ("fe80::1",
                inet62str(&((struct sockaddr_in6*)&result)->sin6_addr, addr));

  // Should match the default route (not the NIC's network), but match the
  // 2001::... source address per picking rules.
  KEXPECT_EQ(0, str2sin6("fe80:1::2", 100, &dst));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(0,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(AF_INET6, result.sa_family);
  KEXPECT_STREQ("fe80::1",
                inet62str(&((struct sockaddr_in6*)&result)->sin6_addr, addr));

  // As above.
  KEXPECT_EQ(0, str2sin6("1:1::2", 100, &dst));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(0,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(AF_INET6, result.sa_family);
  KEXPECT_STREQ(SRC_IP,
                inet62str(&((struct sockaddr_in6*)&result)->sin6_addr, addr));

  KEXPECT_EQ(0, str2sin6("2::1", 100, &dst));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(0,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(AF_INET6, result.sa_family);
  KEXPECT_STREQ(SRC_IP,
                inet62str(&((struct sockaddr_in6*)&result)->sin6_addr, addr));

  // As above.
  KEXPECT_EQ(0, str2sin6("2001::2", 100, &dst));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(0,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(AF_INET6, result.sa_family);
  KEXPECT_STREQ("2001:0:1::1",
                inet62str(&((struct sockaddr_in6*)&result)->sin6_addr, addr));


  // Test a race condition where appropriate addresses are removed after the IP
  // is routed.
  KTEST_BEGIN("ip_pick_src(): IPv6 address removed after route");
  nic_addr_t saved_addrs[NIC_MAX_ADDRS];
  kspin_lock(&t->nic2.n->lock);
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    saved_addrs[i] = t->nic2.n->addrs[i];
  }
  kspin_unlock(&t->nic2.n->lock);

  test_point_add("ip_pick_src:after_route", &remove_ipv6_hook, t->nic2.n);
  KEXPECT_EQ(0, str2sin6("2001::2", 100, &dst));
  kmemset(&result, 0xab, sizeof(result));
  KEXPECT_EQ(-EADDRNOTAVAIL,
             ip_pick_src((const struct sockaddr*)&dst, sizeof(dst), &result));
  KEXPECT_EQ(1, test_point_remove("ip_pick_src:after_route"));

  kspin_lock(&t->nic2.n->lock);
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    t->nic2.n->addrs[i] = saved_addrs[i];
  }
  kspin_unlock(&t->nic2.n->lock);

  ip_set_default_route(ADDR_INET6, orig_default_nexthop, orig_default_nic);
}

static void send_tests(test_fixture_t* t) {
  KTEST_BEGIN("ip6_send(): too-short packet");
  pbuf_t* pb = pbuf_create(0, 10);
  KEXPECT_EQ(-EINVAL, ip6_send(pb, true));

  KTEST_BEGIN("ip6_send(): invalid version");
  pb = pbuf_create(INET6_HEADER_RESERVE, 0);
  struct in6_addr src, dst;
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &src));
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &dst));
  ip6_add_hdr(pb, &src, &dst, IPPROTO_TCP, 0);
  ip6_hdr_t* hdr = (ip6_hdr_t*)pbuf_get(pb);
  hdr->version_tc_flow = htob32(4 << 28);
  KEXPECT_EQ(-EINVAL, ip6_send(pb, true));

  KTEST_BEGIN("ip6_send(): unroutable packet");
  netaddr_t orig_default_nexthop;
  char orig_default_nic[NIC_MAX_NAME_LEN];
  ip_get_default_route(ADDR_INET6, &orig_default_nexthop, orig_default_nic);
  netaddr_t nexthop;
  nexthop.family = AF_UNSPEC;
  ip_set_default_route(ADDR_INET6, nexthop, "");

  pb = pbuf_create(INET6_HEADER_RESERVE, 0);
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &src));
  KEXPECT_EQ(0, str2inet6("100::2", &dst));
  ip6_add_hdr(pb, &src, &dst, IPPROTO_TCP, 0);
  KEXPECT_EQ(-ENETUNREACH, ip6_send(pb, true));

  ip_set_default_route(ADDR_INET6, orig_default_nexthop, orig_default_nic);


  KTEST_BEGIN("ip6_send(): unavailable source address packet");
  pb = pbuf_create(INET6_HEADER_RESERVE, 0);
  KEXPECT_EQ(0, str2inet6("2001:db8::10", &src));
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &dst));
  ip6_add_hdr(pb, &src, &dst, IPPROTO_TCP, 0);
  KEXPECT_EQ(-EADDRNOTAVAIL, ip6_send(pb, true));


  KTEST_BEGIN("ip6_send(): sending fails");
  pb = pbuf_create(INET6_HEADER_RESERVE, 0);
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &src));
  KEXPECT_EQ(0, str2inet6("2001:db8::1234", &dst));
  ip6_add_hdr(pb, &src, &dst, IPPROTO_TCP, 0);
  char buf[100];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 100));
  KEXPECT_EQ(-EAGAIN, ip6_send(pb, false));
  // Drain the NDP solicit.
  KEXPECT_LT(0, vfs_read(t->nic.fd, buf, 100));
}

static size_t mld_size(int num_addrs) {
  return sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(mld_listener_report_t) +
         num_addrs * sizeof(mld_multicast_record_t);
}

static void send_mld_query(test_ttap_t* tt, const char* src) {
  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE, sizeof(mld_query_t));
  mld_query_t* query = (mld_query_t*)pbuf_get(pb);
  kmemset(query, 0, sizeof(mld_query_t));
  query->hdr.type = ICMPV6_MLD_QUERY;
  query->max_response_code = 32768 - 1;

  ip6_pseudo_hdr_t ip6_phdr;
  KEXPECT_EQ(0, str2inet6(src, &ip6_phdr.src_addr));
  KEXPECT_EQ(0, str2inet6("ff02::1", &ip6_phdr.dst_addr));
  kmemset(&ip6_phdr._zeroes, 0, sizeof(ip6_phdr._zeroes));
  ip6_phdr.next_hdr = IPPROTO_ICMPV6;
  ip6_phdr.payload_len = htob32(pbuf_size(pb));

  query->hdr.checksum =
      ip_checksum2(&ip6_phdr, sizeof(ip6_phdr), pbuf_get(pb), pbuf_size(pb));
  ip6_add_hdr(pb, &ip6_phdr.src_addr, &ip6_phdr.dst_addr, IPPROTO_ICMPV6, 0);

  nic_mac_t eth_dst;
  ip6_multicast_mac(&ip6_phdr.dst_addr, eth_dst.addr);
  eth_add_hdr(pb, &eth_dst, &tt->n->mac, ET_IPV6);
  KEXPECT_EQ(pbuf_size(pb), pbuf_write(tt->fd, &pb));
}

static void multicast_tests(test_fixture_t* t) {
  KTEST_BEGIN("IPv6 multicast query (no groups joined)");
  send_mld_query(&t->nic2, MLD_QUERY_SRC);
  char buf[150];
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));


  KTEST_BEGIN("IPv6 multicast join");
  struct in6_addr addr;
  char pretty[INET6_PRETTY_LEN];
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &addr));
  KEXPECT_EQ(-EINVAL, ip6_multicast_join(t->nic2.n, &addr));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));

  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_join(t->nic2.n, &addr));

  KEXPECT_EQ(mld_size(1), vfs_read(t->nic2.fd, buf, 150));
  const eth_hdr_t* eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  const ip6_hdr_t* ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  const mld_listener_report_t* report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  const mld_multicast_record_t* record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_EXCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic2, MLD_QUERY_SRC);
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic2.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_MODE_IS_EXCLUDE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));
  // TODO(ipv6): verify it subscribes on the NIC.


  KTEST_BEGIN("IPv6 multicast query from bad source addr");
  send_mld_query(&t->nic2, "::");
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));
  send_mld_query(&t->nic2, "1::");
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));
  send_mld_query(&t->nic2, "2001:db8::1");
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));


  KTEST_BEGIN("IPv6 multicast join (second)");
  // A second join shouldn't trigger any updates.
  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_join(t->nic2.n, &addr));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));


  KTEST_BEGIN("IPv6 multicast join (a second multicast address)");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff56:3412", &addr));
  KEXPECT_EQ(0, ip6_multicast_join(t->nic2.n, &addr));

  KEXPECT_EQ(mld_size(1), vfs_read(t->nic2.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_EXCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff56:3412",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic2, MLD_QUERY_SRC);
  KEXPECT_EQ(mld_size(2), vfs_read(t->nic2.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + 2 * sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(2, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_MODE_IS_EXCLUDE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  record = &report->records[1];
  KEXPECT_EQ(MLD_MODE_IS_EXCLUDE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff56:3412",
                inet62str(&record->multicast_addr, pretty));
  // TODO(ipv6): verify it subscribes on the NIC.


  KTEST_BEGIN("IPv6 multicast leave (not last join)");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_leave(t->nic2.n, &addr));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));


  KTEST_BEGIN("IPv6 multicast leave (last join)");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_leave(t->nic2.n, &addr));

  KEXPECT_EQ(mld_size(1), vfs_read(t->nic2.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_INCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic2, MLD_QUERY_SRC);
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic2.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_MODE_IS_EXCLUDE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff56:3412",
                inet62str(&record->multicast_addr, pretty));
  // TODO(ipv6): verify it UNsubscribes on the NIC.

  KTEST_BEGIN("IPv6 multicast leave (last join #2)");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff56:3412", &addr));
  KEXPECT_EQ(0, ip6_multicast_leave(t->nic2.n, &addr));
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic2.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic2.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_INCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff56:3412",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic2, MLD_QUERY_SRC);
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic2.fd, buf, 150));
  // TODO(ipv6): verify it UNsubscribes on the NIC.
}

static void multicast_tests2(test_fixture_t* t) {
  KTEST_BEGIN("IPv6 multicast join (no link-local address");
  struct in6_addr addr;
  char pretty[INET6_PRETTY_LEN];
  char buf[150];
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &addr));
  KEXPECT_EQ(-EINVAL, ip6_multicast_join(t->nic.n, &addr));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 150));

  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_join(t->nic.n, &addr));

  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  const eth_hdr_t* eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  const ip6_hdr_t* ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  const mld_listener_report_t* report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  const mld_multicast_record_t* record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_EXCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic, MLD_QUERY_SRC);
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_MODE_IS_EXCLUDE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));
  // TODO(ipv6): verify it subscribes on the NIC.

  KTEST_BEGIN("IPv6 multicast leave (no link-local address)");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_leave(t->nic.n, &addr));
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_INCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic, MLD_QUERY_SRC);
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 150));

  KTEST_BEGIN("IPv6 multicast join (tentative link-local address");
  kspin_lock(&t->nic.n->lock);
  nic_addr_t* new_addr =
      nic_add_addr_v6(t->nic.n, "fe80::1", 64, NIC_ADDR_TENTATIVE);
  kspin_unlock(&t->nic.n->lock);
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &addr));
  KEXPECT_EQ(-EINVAL, ip6_multicast_join(t->nic.n, &addr));
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 150));

  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_join(t->nic.n, &addr));

  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_EXCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic, MLD_QUERY_SRC);
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_MODE_IS_EXCLUDE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));
  // TODO(ipv6): verify it subscribes on the NIC.

  KTEST_BEGIN("IPv6 multicast leave (no link-local address)");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3456", &addr));
  KEXPECT_EQ(0, ip6_multicast_leave(t->nic.n, &addr));
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(t->nic.mac, mac2str(eth_hdr->mac_src, pretty));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, pretty));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, pretty));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, pretty));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_INCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff12:3456",
                inet62str(&record->multicast_addr, pretty));

  send_mld_query(&t->nic, MLD_QUERY_SRC);
  KEXPECT_EQ(-EAGAIN, vfs_read(t->nic.fd, buf, 150));

  KTEST_BEGIN("IPv6 multicast NIC cleanup");
  KEXPECT_EQ(0, str2inet6("ff02::1:ff12:3457", &addr));
  KEXPECT_EQ(0, ip6_multicast_join(t->nic.n, &addr));
  KEXPECT_EQ(mld_size(1), vfs_read(t->nic.fd, buf, 150));
  // Leave the multicast entry on the NIC intentionally to ensure NIC cleanup
  // destroys the table correctly.

  kspin_lock(&t->nic.n->lock);
  new_addr->state = NIC_ADDR_NONE;
  kspin_unlock(&t->nic.n->lock);
}

static void basic_configure_test(void) {
  KTEST_BEGIN("IPv6 basic address configuration (test setup)");
  test_ttap_t nic;
  KEXPECT_EQ(0, test_ttap_create(&nic, TUNTAP_TAP_MODE));
  nic_ipv6_options_t opts = *ipv6_default_nic_opts();
  opts.autoconfigure = false;
  opts.dup_detection_timeout_ms = 50;
  ipv6_enable(nic.n, &opts);


  KTEST_BEGIN("IPv6 basic address configuration: invalid address");
  network_t addr;
  addr.addr.family = AF_INET;
  KEXPECT_EQ(-EINVAL, ipv6_configure_addr(nic.n, &addr));
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &addr.addr.a.ip6));
  addr.addr.family = AF_INET6;
  addr.prefix_len = 0;
  KEXPECT_EQ(-EINVAL, ipv6_configure_addr(nic.n, &addr));
  addr.prefix_len = 129;
  KEXPECT_EQ(-EINVAL, ipv6_configure_addr(nic.n, &addr));
  kspin_lock(&nic.n->lock);
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    KEXPECT_EQ(NIC_ADDR_NONE, nic.n->addrs[i].state);
  }
  kspin_unlock(&nic.n->lock);
  char buf[300];
  KEXPECT_EQ(-EAGAIN, vfs_read(nic.fd, buf, 300));


  KTEST_BEGIN("IPv6 basic address configuration");
  // Configure an address (which should NOT be used in this process).
  kspin_lock(&nic.n->lock);
  nic.n->addrs[0].state = NIC_ADDR_ENABLED;
  KEXPECT_EQ(0, str2inet6("fe80::1", &nic.n->addrs[0].a.addr.a.ip6));
  nic.n->addrs[0].a.addr.family = AF_INET6;
  nic.n->addrs[0].a.prefix_len = 64;
  kspin_unlock(&nic.n->lock);

  KEXPECT_EQ(0, str2inet6("2001:db8::1234:5678", &addr.addr.a.ip6));
  addr.addr.family = AF_INET6;
  addr.prefix_len = 96;
  KEXPECT_EQ(0, ipv6_configure_addr(nic.n, &addr));

  kspin_lock(&nic.n->lock);
  KEXPECT_EQ(NIC_ADDR_ENABLED, nic.n->addrs[0].state);
  KEXPECT_EQ(AF_INET6, nic.n->addrs[0].a.addr.family);
  KEXPECT_EQ(64, nic.n->addrs[0].a.prefix_len);
  KEXPECT_STREQ("fe80::1",
                inet62str(&nic.n->addrs[0].a.addr.a.ip6, buf));

  KEXPECT_EQ(NIC_ADDR_TENTATIVE, nic.n->addrs[1].state);
  KEXPECT_EQ(AF_INET6, nic.n->addrs[1].a.addr.family);
  KEXPECT_EQ(96, nic.n->addrs[1].a.prefix_len);
  KEXPECT_STREQ("2001:db8::1234:5678",
                inet62str(&nic.n->addrs[1].a.addr.a.ip6, buf));
  for (int i = 2; i < NIC_MAX_ADDRS; ++i) {
    KEXPECT_EQ(NIC_ADDR_NONE, nic.n->addrs[i].state);
  }
  kspin_unlock(&nic.n->lock);

  // We should have first gotten an MLD update to subscribe to the new address.
  char mac[NIC_MAC_PRETTY_LEN];
  char addrstr[INET6_PRETTY_LEN];

  KEXPECT_EQ(mld_size(1), vfs_read(nic.fd, buf, 150));
  const eth_hdr_t* eth_hdr = (eth_hdr_t*)&buf[0];
  KEXPECT_STREQ(nic.mac, mac2str(eth_hdr->mac_src, addrstr));
  KEXPECT_STREQ("33:33:00:00:00:16", mac2str(eth_hdr->mac_dst, addrstr));
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));

  const ip6_hdr_t* ip6_hdr = (ip6_hdr_t*)(eth_hdr + 1);
  KEXPECT_STREQ("fe80::1", inet62str(&ip6_hdr->src_addr, addrstr));
  KEXPECT_STREQ("ff02::16", inet62str(&ip6_hdr->dst_addr, addrstr));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);
  KEXPECT_EQ(sizeof(mld_listener_report_t) + sizeof(mld_multicast_record_t),
             btoh16(ip6_hdr->payload_len));

  const mld_listener_report_t* report = (mld_listener_report_t*)(ip6_hdr + 1);
  KEXPECT_EQ(143, report->hdr.type);
  KEXPECT_EQ(0, report->hdr.code);
  KEXPECT_EQ(1, btoh16(report->num_mc_records));
  KEXPECT_EQ(0, report->reserved);

  const mld_multicast_record_t* record = &report->records[0];
  KEXPECT_EQ(MLD_CHANGE_TO_EXCLUDE_MODE, record->record_type);
  KEXPECT_EQ(0, btoh16(record->num_sources));
  KEXPECT_EQ(0, btoh16(record->aux_data_len));
  KEXPECT_STREQ("ff02::1:ff34:5678",
                inet62str(&record->multicast_addr, addrstr));

  // We should have then gotten a neighbor solicitation for the address.
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t),
      vfs_read(nic.fd, buf, 300));
  // First check ethernet header.
  KEXPECT_EQ(ET_IPV6, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(nic.mac, mac2str(eth_hdr->mac_src, mac));
  KEXPECT_STREQ("33:33:FF:34:56:78", mac2str(eth_hdr->mac_dst, mac));

  // ...then the IPv6 header.
  ip6_hdr = (const ip6_hdr_t*)((uint8_t*)&buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(6, ip6_version(*ip6_hdr));
  KEXPECT_EQ(sizeof(ndp_nbr_solict_t), btoh16(ip6_hdr->payload_len));
  KEXPECT_EQ(IPPROTO_ICMPV6, ip6_hdr->next_hdr);

  KEXPECT_STREQ("::", inet62str(&ip6_hdr->src_addr, addrstr));
  // The solicited-node multicast address for the requested IP.
  KEXPECT_STREQ("ff02::1:ff34:5678", inet62str(&ip6_hdr->dst_addr, addrstr));

  // ...then the ICMPv6 and NDP headers.
  const ndp_nbr_solict_t* pkt =
      (const ndp_nbr_solict_t*)((uint8_t*)ip6_hdr + sizeof(ip6_hdr_t));
  KEXPECT_EQ(135, pkt->hdr.type);
  KEXPECT_EQ(0, pkt->hdr.code);
  KEXPECT_EQ(0, pkt->reserved);
  KEXPECT_STREQ("2001:db8::1234:5678", inet62str(&pkt->target, addrstr));

  // Now wait for the timer to time out.
  ksleep(50);

  // Should have no more packets, and the address should be configured.
  KEXPECT_EQ(-EAGAIN, vfs_read(nic.fd, buf, 300));

  kspin_lock(&nic.n->lock);
  KEXPECT_EQ(NIC_ADDR_ENABLED, nic.n->addrs[0].state);
  KEXPECT_EQ(AF_INET6, nic.n->addrs[0].a.addr.family);
  KEXPECT_EQ(64, nic.n->addrs[0].a.prefix_len);
  KEXPECT_STREQ("fe80::1",
                inet62str(&nic.n->addrs[0].a.addr.a.ip6, buf));

  KEXPECT_EQ(NIC_ADDR_ENABLED, nic.n->addrs[1].state);
  KEXPECT_EQ(AF_INET6, nic.n->addrs[1].a.addr.family);
  KEXPECT_EQ(96, nic.n->addrs[1].a.prefix_len);
  KEXPECT_STREQ("2001:db8::1234:5678",
                inet62str(&nic.n->addrs[1].a.addr.a.ip6, buf));
  for (int i = 2; i < NIC_MAX_ADDRS; ++i) {
    KEXPECT_EQ(NIC_ADDR_NONE, nic.n->addrs[i].state);
  }
  kspin_unlock(&nic.n->lock);

  test_ttap_destroy(&nic);
}

// Variant 1 has a timeout that we make sure expires during the test, and after
// we delete the NIC.  This confirms that either the timer is cancelled, or
// memory is otherwise managed correctly.
static void configure_nic_delete_test(void) {
  KTEST_BEGIN("IPv6 NIC deletion during configuration");
  test_ttap_t nic;
  KEXPECT_EQ(0, test_ttap_create(&nic, TUNTAP_TAP_MODE));
  nic_ipv6_options_t opts = *ipv6_default_nic_opts();
  opts.autoconfigure = false;
  opts.dup_detection_timeout_ms = 50;
  ipv6_enable(nic.n, &opts);

  network_t addr;
  char buf[300];
  KEXPECT_EQ(-EAGAIN, vfs_read(nic.fd, buf, 300));

  // Configure an address (which should NOT be used in this process).
  kspin_lock(&nic.n->lock);
  nic.n->addrs[0].state = NIC_ADDR_ENABLED;
  KEXPECT_EQ(0, str2inet6("fe80::1", &nic.n->addrs[0].a.addr.a.ip6));
  nic.n->addrs[0].a.addr.family = AF_INET6;
  nic.n->addrs[0].a.prefix_len = 64;
  kspin_unlock(&nic.n->lock);

  KEXPECT_EQ(0, str2inet6("2001:db8::1234:5678", &addr.addr.a.ip6));
  addr.addr.family = AF_INET6;
  addr.prefix_len = 96;
  KEXPECT_EQ(0, ipv6_configure_addr(nic.n, &addr));

  kspin_lock(&nic.n->lock);
  KEXPECT_EQ(NIC_ADDR_TENTATIVE, nic.n->addrs[1].state);
  KEXPECT_EQ(AF_INET6, nic.n->addrs[1].a.addr.family);
  KEXPECT_EQ(96, nic.n->addrs[1].a.prefix_len);
  KEXPECT_STREQ("2001:db8::1234:5678",
                inet62str(&nic.n->addrs[1].a.addr.a.ip6, buf));
  kspin_unlock(&nic.n->lock);

  // We should have gotten an MLD update and NDP request.
  KEXPECT_EQ(mld_size(1), vfs_read(nic.fd, buf, 150));
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t),
      vfs_read(nic.fd, buf, 300));

  // Destroy the NIC before the timer triggers.
  test_ttap_destroy(&nic);

  // Wait until the timer would have triggered.
  ksleep(60);
}

// Variant 2 has a timeout that expires long in the future, verifying there are
// no memory leaks and the timer is cancelled.  This is arguably over-testing
// --- it could be valid for the code to let the timer complete so long as it
// doesn't reference any freed memory.
static void configure_nic_delete_test2(void) {
  KTEST_BEGIN("IPv6 NIC deletion during configuration (long timeout)");
  test_ttap_t nic;
  KEXPECT_EQ(0, test_ttap_create(&nic, TUNTAP_TAP_MODE));
  nic_ipv6_options_t opts = *ipv6_default_nic_opts();
  opts.autoconfigure = false;
  opts.dup_detection_timeout_ms = 60000;
  ipv6_enable(nic.n, &opts);

  network_t addr;
  char buf[300];
  KEXPECT_EQ(-EAGAIN, vfs_read(nic.fd, buf, 300));

  // Configure an address (which should NOT be used in this process).
  kspin_lock(&nic.n->lock);
  nic.n->addrs[0].state = NIC_ADDR_ENABLED;
  KEXPECT_EQ(0, str2inet6("fe80::1", &nic.n->addrs[0].a.addr.a.ip6));
  nic.n->addrs[0].a.addr.family = AF_INET6;
  nic.n->addrs[0].a.prefix_len = 64;
  kspin_unlock(&nic.n->lock);

  KEXPECT_EQ(0, str2inet6("2001:db8::1234:5678", &addr.addr.a.ip6));
  addr.addr.family = AF_INET6;
  addr.prefix_len = 96;
  KEXPECT_EQ(0, ipv6_configure_addr(nic.n, &addr));

  kspin_lock(&nic.n->lock);
  KEXPECT_EQ(NIC_ADDR_TENTATIVE, nic.n->addrs[1].state);
  KEXPECT_EQ(AF_INET6, nic.n->addrs[1].a.addr.family);
  KEXPECT_EQ(96, nic.n->addrs[1].a.prefix_len);
  KEXPECT_STREQ("2001:db8::1234:5678",
                inet62str(&nic.n->addrs[1].a.addr.a.ip6, buf));
  kspin_unlock(&nic.n->lock);

  // We should have gotten an MLD update and NDP request.
  KEXPECT_EQ(mld_size(1), vfs_read(nic.fd, buf, 150));
  KEXPECT_EQ(
      sizeof(eth_hdr_t) + sizeof(ip6_hdr_t) + sizeof(ndp_nbr_solict_t),
      vfs_read(nic.fd, buf, 300));

  // Destroy the NIC before the timer triggers.
  test_ttap_destroy(&nic);
}

static void configure_tests(test_fixture_t* t) {
  basic_configure_test();
  configure_nic_delete_test();
  configure_nic_delete_test2();
  // TODO(ipv6): more configuration tests:
  // - duplicate detection finds dup
  // - no address spots left
  // - address already configured (inc. in a later slot)
  // - simultaneous duplicate address detections
  // - autoconfigure does link-local address
  // - autoconfigure does link-local address (and conflict)
}

// TODO(ipv6): additional tests:
//  - invalid IPv6 packets
//  - invalid NDP packets (including options)
//  - too-short ipv6 and icmp and NDP packets.

void ipv6_test(void) {
  KTEST_SUITE_BEGIN("IPv6");
  KTEST_BEGIN("IPv6: test setup");
  test_fixture_t fixture;
  KEXPECT_EQ(0, test_ttap_create(&fixture.nic, TUNTAP_TAP_MODE));
  nic_ipv6_options_t opts = *ipv6_default_nic_opts();
  opts.autoconfigure = false;
  ipv6_enable(fixture.nic.n, &opts);

  kspin_lock(&fixture.nic.n->lock);
  nic_add_addr_v6(fixture.nic.n, SRC_IP, 64, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic.n, SRC_IP2, 64, NIC_ADDR_ENABLED);
  nic_addr_t* disable_addr1 =
      nic_add_addr_v6(fixture.nic.n, DISABLED_SRC_IP, 64, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic.n, DISABLED_SRC_IP2, 64, NIC_ADDR_TENTATIVE);
  nic_add_addr_v6(fixture.nic.n, "0102:0304::", 64, NIC_ADDR_ENABLED)
      ->a.addr.family = AF_INET;

  disable_addr1->state = NIC_ADDR_NONE;
  kspin_unlock(&fixture.nic.n->lock);

  KEXPECT_EQ(0, test_ttap_create(&fixture.nic2, TUNTAP_TAP_MODE));
  ipv6_enable(fixture.nic2.n, &opts);

  kspin_lock(&fixture.nic2.n->lock);
  nic_add_addr(fixture.nic2.n, "1.2.3.4", 24, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic2.n, SRC_IP, 64, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic2.n, SRC_IP2, 64, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic2.n, "1::1", 64, NIC_ADDR_TENTATIVE);
  nic_add_addr_v6(fixture.nic2.n, "fe80::1", 64, NIC_ADDR_ENABLED);
  nic_add_addr_v6(fixture.nic2.n, "2001:0:1::1", 64, NIC_ADDR_ENABLED);
  kspin_unlock(&fixture.nic2.n->lock);

  // Run the tests.
  addr_tests();
  netaddr_tests();
  sockaddr_tests();
  pkt_tests();
  ndp_tests(&fixture);
  addr_selection_tests(&fixture);
  pick_src_ip_tests(&fixture);
  send_tests(&fixture);
  multicast_tests(&fixture);
  multicast_tests2(&fixture);
  configure_tests(&fixture);

  KTEST_BEGIN("IPv6: test teardown");
  test_ttap_destroy(&fixture.nic);
  test_ttap_destroy(&fixture.nic2);
}
