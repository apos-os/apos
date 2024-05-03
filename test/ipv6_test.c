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
#include "net/util.h"
#include "test/ktest.h"

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

void ipv6_test(void) {
  KTEST_SUITE_BEGIN("IPv6");
  addr_tests();
}
