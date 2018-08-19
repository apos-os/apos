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
#include "memory/block_cache.h"
#include "net/socket/socket.h"
#include "net/util.h"
#include "test/ktest.h"
#include "user/include/apos/errors.h"
#include "vfs/pipe.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static void getsockname_test(void) {
  struct sockaddr_storage addr;

  KTEST_BEGIN("net_getsockname(): bad FD");
  KEXPECT_EQ(-EBADF, net_getsockname(-5, (struct sockaddr*)&addr));

  KTEST_BEGIN("net_getpeername(): bad FD");
  KEXPECT_EQ(-EBADF, net_getpeername(-5, (struct sockaddr*)&addr));

  KTEST_BEGIN("net_getsockname(): non-socket FD");
  int pipe[2];
  KEXPECT_EQ(0, vfs_pipe(pipe));
  KEXPECT_EQ(-ENOTSOCK, net_getsockname(pipe[0], (struct sockaddr*)&addr));

  KTEST_BEGIN("net_getpeername(): non-socket FD");
  KEXPECT_EQ(-ENOTSOCK, net_getpeername(pipe[0], (struct sockaddr*)&addr));

  vfs_close(pipe[0]);
  vfs_close(pipe[1]);
}

void socket_test(void) {
  KTEST_SUITE_BEGIN("Socket");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

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

  getsockname_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
