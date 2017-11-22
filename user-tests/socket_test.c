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

#include <apos/syscall_decls.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ktest.h"

static void socket_unix_test(void) {
  KTEST_SUITE_BEGIN("Unix Domain Sockets test");
  KTEST_BEGIN("socket(AF_UNIX): create/bind/listen test");
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, "_socket_bind");
  KEXPECT_EQ(0, bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KEXPECT_EQ(0, listen(sock, 5));

  KTEST_BEGIN("socket(AF_UNIX): connect test");
  int s1 = socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(s1, 0);
  KEXPECT_EQ(0, connect(s1, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("socket(AF_UNIX): accept test");
  memset(&addr, 0, sizeof(addr));
  socklen_t addr_len = sizeof(addr);
  int s2 = accept(sock, (struct sockaddr*)&addr, &addr_len);
  KEXPECT_GE(s2, 0);

  KTEST_BEGIN("socket(AF_UNIX): read/write test");
  KEXPECT_EQ(3, write(s1, "abc", 3));
  KEXPECT_EQ(3, write(s2, "def", 3));
  char buf[10];
  KEXPECT_EQ(3, read(s1, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("def", buf);
  KEXPECT_EQ(3, read(s2, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  KTEST_BEGIN("socket(AF_UNIX): shutdown test");
  KEXPECT_EQ(0, shutdown(s1, SHUT_WR));
  KEXPECT_EQ(0, read(s2, buf, 10));
  KEXPECT_EQ(0, close(s1));
  KEXPECT_EQ(0, close(s2));
  KEXPECT_EQ(0, close(sock));
  KEXPECT_EQ(0, unlink("_socket_bind"));

  KTEST_BEGIN("accept(): bad buffer parameters");
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  int result = accept(sock, NULL, NULL);
  int e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  result = accept(sock, (struct sockaddr*)&addr, NULL);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  result = accept(sock, NULL, &addr_len);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  result = accept(sock, (struct sockaddr*)&addr, (socklen_t*)0x123);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EFAULT, e);

  result = accept(sock, (struct sockaddr*)0x123, &addr_len);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EFAULT, e);

  result = accept(sock, (struct sockaddr*)0x123, (socklen_t*)0x123);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EFAULT, e);

  KEXPECT_EQ(0, close(sock));
}

void socket_test(void) {
  socket_unix_test();
}
