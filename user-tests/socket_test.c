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
#include <assert.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>

#include "ktest.h"

static void connect_and_close(const char* path) {
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(sock >= 0);
  assert(0 == connect(sock, (struct sockaddr*)&addr, sizeof(addr)));
  assert(0 == close(sock));
}

static void socket_unix_test(void) {
  KTEST_SUITE_BEGIN("Unix Domain Sockets test");
  KTEST_BEGIN("socket(AF_UNIX): create/bind/listen test");
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, "_socket_bind");
  KEXPECT_SIGNAL(SIGSEGV, bind(sock, NULL, sizeof(addr)));
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

  KTEST_BEGIN("accept(): NULL buffer parameters");
  connect_and_close("_socket_bind");
  int result = accept(sock, NULL, NULL);
  KEXPECT_GE(result, 0);
  KEXPECT_EQ(0, close(result));

  connect_and_close("_socket_bind");
  result = accept(sock, (struct sockaddr*)&addr, NULL);
  KEXPECT_GE(result, 0);
  KEXPECT_EQ(0, close(result));

  connect_and_close("_socket_bind");
  result = accept(sock, NULL, &addr_len);
  KEXPECT_GE(result, 0);
  KEXPECT_EQ(0, close(result));


  KTEST_BEGIN("accept(): bad buffer parameters");
  connect_and_close("_socket_bind");
  KEXPECT_SIGNAL(SIGSEGV,
                 accept(sock, (struct sockaddr*)&addr, (socklen_t*)0x123));

  // TODO(aoates): update accept_wrapper() so this also generates SIGSEGV.
  KEXPECT_ERRNO(EFAULT, accept(sock, (struct sockaddr*)0x123, &addr_len));

  connect_and_close("_socket_bind");
  KEXPECT_SIGNAL(SIGSEGV,
                 accept(sock, (struct sockaddr*)0x123, (socklen_t*)0x123));

  KTEST_BEGIN("connect(): bad buffer parameters");
  result = connect(sock, NULL, 0);
  int e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  result = connect(sock, (struct sockaddr*)&addr, 0);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  KEXPECT_ERRNO(ENOMEM, connect(sock, (struct sockaddr*)&addr, INT_MAX));
  KEXPECT_ERRNO(EINVAL, connect(sock, (struct sockaddr*)&addr, 0));
  KEXPECT_ERRNO(EINVAL, connect(sock, (struct sockaddr*)&addr, 1));
  KEXPECT_ERRNO(EINVAL, connect(sock, (struct sockaddr*)&addr, -10));

  KEXPECT_SIGNAL(SIGSEGV, connect(sock, NULL, sizeof(addr)));

  KEXPECT_SIGNAL(SIGSEGV, connect(sock, (struct sockaddr*)0x123, sizeof(addr)));

  KTEST_BEGIN("sendto(): bad buffer parameters");
  result = sendto(sock, buf, 10, 0, NULL, 0);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  result = sendto(sock, buf, 10, 0, (struct sockaddr*)&addr, 0);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  KEXPECT_ERRNO(ENOMEM,
                sendto(sock, buf, 10, 0, (struct sockaddr*)&addr, INT_MAX));

  // NULL addr should be allowed.
  result = sendto(sock, buf, 10, 0, NULL, sizeof(addr));
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  KEXPECT_SIGNAL(
      SIGSEGV, sendto(sock, buf, 10, 0, (struct sockaddr*)0x123, sizeof(addr)));

  KEXPECT_ERRNO(ENOMEM, sendto(sock, buf, INT_MAX, 0, NULL, 0));

  KEXPECT_SIGNAL(SIGSEGV, sendto(sock, (void*)0x123, 10, 0, NULL, 0));

  KEXPECT_SIGNAL(SIGSEGV, sendto(sock, NULL, 10, 0, NULL, 0));

  KTEST_BEGIN("recvfrom(): bad buffer parameters");
  result = recvfrom(sock, buf, 10, 0, NULL, 0);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  result = recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr, 0);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr,
                                   (socklen_t*)INT_MAX));

  socklen_t len = INT_MAX;
  KEXPECT_ERRNO(EFAULT,
                recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr, &len));

  // NULL addr should be allowed.
  len = sizeof(addr);
  result = recvfrom(sock, buf, 10, 0, NULL, &len);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  // TODO(aoates): update recvfrom wrapper to generate SIGSEGV here.
  KEXPECT_ERRNO(EFAULT,
                recvfrom(sock, buf, 10, 0, (struct sockaddr*)0x123, &len));

  KEXPECT_ERRNO(ENOMEM, recvfrom(sock, buf, INT_MAX, 0, NULL, 0));

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr,
                                   (socklen_t*)0x123));

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, (void*)0x123, 10, 0, NULL, 0));

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, NULL, 10, 0, NULL, 0));

  KEXPECT_EQ(0, close(sock));
  KEXPECT_EQ(0, unlink("_socket_bind"));
}

void socket_test(void) {
  socket_unix_test();
}
