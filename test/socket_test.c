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

#include "test/kernel_tests.h"

#include "arch/common/endian.h"
#include "net/socket/socket.h"
#include "net/util.h"
#include "test/ktest.h"
#include "user/include/apos/errors.h"

void socket_test(void) {
  KTEST_SUITE_BEGIN("Socket");

  KTEST_BEGIN("net_socket_create() with invalid domain");
  socket_t* sock = NULL;
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket_create(-1, SOCK_STREAM, 0, &sock));
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket_create(5, SOCK_STREAM, 0, &sock));
  KEXPECT_EQ(NULL, sock);

  KTEST_BEGIN("net_socket() with invalid domain");
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket(-1, SOCK_STREAM, 0));
  KEXPECT_EQ(-EAFNOSUPPORT, net_socket(5, SOCK_STREAM, 0));

  KTEST_BEGIN("inet2str() tests");
  char buf[INET_PRETTY_LEN];
  const char* bufptr = &buf[0];
  KEXPECT_EQ(bufptr, inet2str(0xffffffff, buf));
  KEXPECT_STREQ("255.255.255.255", buf);
  KEXPECT_EQ(bufptr, inet2str(0x0, buf));
  KEXPECT_STREQ("0.0.0.0", buf);
  KEXPECT_EQ(bufptr, inet2str(htob32(0x01020304), buf));
  KEXPECT_STREQ("1.2.3.4", buf);

  KTEST_BEGIN("str2inet() tests");
  KEXPECT_EQ(0, str2inet("0.0.0.0"));
  KEXPECT_EQ(htob32(0x01020304), str2inet("1.2.3.4"));
  KEXPECT_EQ(htob32(0xFFFEFDFC), str2inet("255.254.253.252"));
  KEXPECT_EQ(htob32(0x00000001), str2inet("0.0.0.1"));
  KEXPECT_EQ(htob32(0x01000000), str2inet("1.0.0.0"));
  KEXPECT_EQ(0, str2inet("256.254.253.252"));
  KEXPECT_EQ(0, str2inet("1.256.253.252"));
  KEXPECT_EQ(0, str2inet("-1.1.2.1"));
  KEXPECT_EQ(0, str2inet("1.-1.253.252"));
  KEXPECT_EQ(0, str2inet("1.a1.1.1"));
  KEXPECT_EQ(0, str2inet("a1.1.1.1"));
  KEXPECT_EQ(0, str2inet("1.1.1.1.1"));
  KEXPECT_EQ(0, str2inet("1.a.1.1"));
  KEXPECT_EQ(0, str2inet("1.z.1.1"));
  KEXPECT_EQ(0, str2inet("abcd"));
  KEXPECT_EQ(0, str2inet(""));
  KEXPECT_EQ(0, str2inet(".1.1.1"));
  KEXPECT_EQ(0, str2inet(".1.1.1.1"));
  KEXPECT_EQ(0, str2inet("1"));
  KEXPECT_EQ(0, str2inet("1."));
  KEXPECT_EQ(0, str2inet("1.1"));
  KEXPECT_EQ(0, str2inet("1.1.1"));
  KEXPECT_EQ(0, str2inet("1.1.1."));
}
