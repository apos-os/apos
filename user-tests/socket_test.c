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
  struct sockaddr_un addr_client;
  addr_client.sun_family = AF_UNIX;
  strcpy(addr_client.sun_path, "_socket_client");
  KEXPECT_EQ(0, bind(s1, (struct sockaddr*)&addr_client, sizeof(addr_client)));
  KEXPECT_EQ(0, connect(s1, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("socket(AF_UNIX): accept test");
  memset(&addr, 0, sizeof(addr));
  socklen_t addr_len = sizeof(addr);
  int s2 = accept(sock, (struct sockaddr*)&addr, &addr_len);
  KEXPECT_GE(s2, 0);
  KEXPECT_EQ(AF_UNIX, addr.sun_family);
  KEXPECT_STREQ("_socket_client", addr.sun_path);

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
  KEXPECT_EQ(0, unlink("_socket_client"));

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

  connect_and_close("_socket_bind");
  KEXPECT_SIGNAL(SIGSEGV, accept(sock, (struct sockaddr*)0x123, &addr_len));

  connect_and_close("_socket_bind");
  KEXPECT_SIGNAL(SIGSEGV,
                 accept(sock, (struct sockaddr*)0x123, (socklen_t*)0x123));

  addr_len = INT_MAX;
  KEXPECT_ERRNO(EINVAL, accept(sock, (struct sockaddr*)&addr, &addr_len));
  addr_len = 0;
  KEXPECT_ERRNO(EINVAL, accept(sock, (struct sockaddr*)&addr, &addr_len));
  addr_len = -1;
  KEXPECT_ERRNO(EINVAL, accept(sock, (struct sockaddr*)&addr, &addr_len));

  KTEST_BEGIN("connect(): bad buffer parameters");
  result = connect(sock, NULL, 0);
  int e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  result = connect(sock, (struct sockaddr*)&addr, 0);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(EINVAL, e);

  KEXPECT_ERRNO(EINVAL, connect(sock, (struct sockaddr*)&addr, INT_MAX));
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

  KEXPECT_ERRNO(EINVAL,
                sendto(sock, buf, 10, 0, (struct sockaddr*)&addr, INT_MAX));

  // NULL addr should be allowed.
  result = sendto(sock, buf, 10, 0, NULL, sizeof(addr));
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  KEXPECT_SIGNAL(
      SIGSEGV, sendto(sock, buf, 10, 0, (struct sockaddr*)0x123, sizeof(addr)));

  KEXPECT_ERRNO(EINVAL, sendto(sock, buf, INT_MAX, 0, NULL, 0));

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
  KEXPECT_ERRNO(EINVAL,
                recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr, &len));
  len = -1;
  KEXPECT_ERRNO(EINVAL,
                recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr, &len));

  // NULL addr should be allowed.
  len = sizeof(addr);
  result = recvfrom(sock, buf, 10, 0, NULL, &len);
  e = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ENOTCONN, e);

  KEXPECT_SIGNAL(SIGSEGV,
                 recvfrom(sock, buf, 10, 0, (struct sockaddr*)0x123, &len));

  KEXPECT_ERRNO(EINVAL, recvfrom(sock, buf, INT_MAX, 0, NULL, 0));

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, buf, 10, 0, (struct sockaddr*)&addr,
                                   (socklen_t*)0x123));

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, (void*)0x123, 10, 0, NULL, 0));

  KEXPECT_SIGNAL(SIGSEGV, recvfrom(sock, NULL, 10, 0, NULL, 0));

  KEXPECT_EQ(0, close(sock));
  KEXPECT_EQ(0, unlink("_socket_bind"));
}

static void sockopt_test(void) {
  KTEST_SUITE_BEGIN("Socket options tests");
  KTEST_BEGIN("getsockopt(): basic test");
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(sock, 0);

  int val[2];
  socklen_t len = 2 * sizeof(int);
  KEXPECT_EQ(0, getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &len));
  KEXPECT_EQ(SOCK_DGRAM, val[0]);
  KEXPECT_EQ(sizeof(int), len);
  KEXPECT_ERRNO(EBADF, getsockopt(-1, SOL_SOCKET, SO_TYPE, &val[0], &len));
  KEXPECT_ERRNO(EBADF, getsockopt(1000, SOL_SOCKET, SO_TYPE, &val[0], &len));


  KTEST_BEGIN("setsockopt(): basic test");
  len = sizeof(int);
  KEXPECT_ERRNO(ENOPROTOOPT,
                setsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], len));
  KEXPECT_ERRNO(EBADF,
                setsockopt(-1, SOL_SOCKET, SO_TYPE, &val[0], len));
  KEXPECT_ERRNO(EBADF,
                setsockopt(1000, SOL_SOCKET, SO_TYPE, &val[0], len));


  KTEST_BEGIN("getsockopt(): bad buffers test");
  len = sizeof(int);
  void* addr1 = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  KEXPECT_NE(NULL, addr1);
  KEXPECT_EQ(0, munmap(addr1 + 4096, 4096));
  void* bad_buf = addr1 + 4096;
  void* partial_bad_buf = addr1 + 4094;

  len = sizeof(int);
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(sock, SOL_SOCKET, SO_TYPE, bad_buf, &len));
  KEXPECT_SIGNAL(SIGSEGV,
                 getsockopt(sock, SOL_SOCKET, SO_TYPE, partial_bad_buf, &len));
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(sock, SOL_SOCKET, SO_TYPE, addr1,
                                     (socklen_t*)bad_buf));
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(sock, SOL_SOCKET, SO_TYPE, addr1,
                                     (socklen_t*)partial_bad_buf));
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(1000, SOL_SOCKET, SO_TYPE, bad_buf, &len));
  KEXPECT_SIGNAL(SIGSEGV,
                 getsockopt(sock, SOL_SOCKET, SO_TYPE, partial_bad_buf, &len));
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(1000, SOL_SOCKET, SO_TYPE, addr1,
                                     (socklen_t*)bad_buf));
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(1000, SOL_SOCKET, SO_TYPE, addr1,
                                     (socklen_t*)partial_bad_buf));
  // Note: this, arguably, could SIGSEGV as well.  The current kernel
  // implementation doesn't check the buffer length until _after_ the call, so
  // this succeeds (since the length at that point is 4 bytes).
  len = 4096 + 100;
  KEXPECT_EQ(0, getsockopt(sock, SOL_SOCKET, SO_TYPE, addr1, &len));
  KEXPECT_EQ(sizeof(int), len);
  // This could segfault or have an error, either would be valid behavior.
  len = 4096 + 100;
  KEXPECT_SIGNAL(SIGSEGV, getsockopt(1000, SOL_SOCKET, SO_TYPE, addr1, &len));


  KTEST_BEGIN("setsockopt(): bad buffers test");
  len = sizeof(int);
  KEXPECT_SIGNAL(SIGSEGV, setsockopt(sock, SOL_SOCKET, SO_TYPE, bad_buf, len));
  KEXPECT_SIGNAL(SIGSEGV,
                 setsockopt(sock, SOL_SOCKET, SO_TYPE, partial_bad_buf, len));


  KEXPECT_EQ(0, munmap(addr1, 4096));
  KEXPECT_EQ(0, close(sock));
}

static void sockname_unix_tests(void) {
  KTEST_SUITE_BEGIN("sockname tests");
  KTEST_BEGIN("getsockname()/getpeername(): AF_UNIX");
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  char buf[200];
  struct sockaddr_un* buf_addr = (struct sockaddr_un*)buf;
  memset(buf, 'x', 200);
  socklen_t len = 200;
  KEXPECT_EQ(0, getsockname(sock, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(sizeof(struct sockaddr_un), len);
  KEXPECT_EQ(AF_UNIX, buf_addr->sun_family);
  KEXPECT_STREQ("", buf_addr->sun_path);
  KEXPECT_EQ('x', buf[len]);

  memset(buf, 'x', 200);
  KEXPECT_ERRNO(ENOTCONN, getpeername(sock, (struct sockaddr*)buf, &len));
  KEXPECT_EQ('x', buf[0]);

  // Create a connected pair.
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, "_socket_bind");
  KEXPECT_EQ(0, bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, listen(sock, 5));

  len = 200;
  KEXPECT_EQ(0, getsockname(sock, (struct sockaddr*)buf, &len));
  KEXPECT_ERRNO(ENOTCONN, getpeername(sock, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(sizeof(struct sockaddr_un), len);
  KEXPECT_EQ(AF_UNIX, buf_addr->sun_family);
  KEXPECT_STREQ("_socket_bind", buf_addr->sun_path);
  KEXPECT_EQ('x', buf[len]);


  int s1 = socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(s1, 0);
  struct sockaddr_un addr_client;
  addr_client.sun_family = AF_UNIX;
  strcpy(addr_client.sun_path, "_socket_client");
  KEXPECT_EQ(0, bind(s1, (struct sockaddr*)&addr_client, sizeof(addr_client)));
  KEXPECT_EQ(0, connect(s1, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("socket(AF_UNIX): accept test");
  memset(&addr, 0, sizeof(addr));
  socklen_t addr_len = sizeof(addr);
  int s2 = accept(sock, (struct sockaddr*)&addr, &addr_len);
  KEXPECT_GE(s2, 0);
  KEXPECT_EQ(AF_UNIX, addr.sun_family);
  KEXPECT_STREQ("_socket_client", addr.sun_path);

  len = 200;
  memset(buf, 'x', 200);
  KEXPECT_EQ(0, getsockname(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(sizeof(struct sockaddr_un), len);
  KEXPECT_EQ(AF_UNIX, buf_addr->sun_family);
  KEXPECT_STREQ("_socket_client", buf_addr->sun_path);
  KEXPECT_EQ('x', buf[len]);

  len = 200;
  memset(buf, 'x', 200);
  KEXPECT_EQ(0, getpeername(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(sizeof(struct sockaddr_un), len);
  KEXPECT_EQ(AF_UNIX, buf_addr->sun_family);
  KEXPECT_STREQ("_socket_bind", buf_addr->sun_path);
  KEXPECT_EQ('x', buf[len]);

  len = 200;
  memset(buf, 'x', 200);
  KEXPECT_EQ(0, getsockname(s2, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(sizeof(struct sockaddr_un), len);
  KEXPECT_EQ(AF_UNIX, buf_addr->sun_family);
  KEXPECT_STREQ("_socket_bind", buf_addr->sun_path);
  KEXPECT_EQ('x', buf[len]);

  // Test small lengths.
  len = 10;
  memset(buf, 'x', 200);
  KEXPECT_EQ(0, getsockname(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(10, len);
  buf[15] = '\0';
  KEXPECT_EQ(AF_UNIX, buf_addr->sun_family);
  KEXPECT_STREQ("_sockexxxxx", buf_addr->sun_path);

  // Test bad lengths.
  len = 0;
  memset(buf, 'x', 200);
  KEXPECT_EQ(0, getsockname(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(0, len);
  KEXPECT_EQ('x', buf[0]);

  len = 0;
  memset(buf, 'x', 200);
  KEXPECT_EQ(0, getpeername(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(0, len);
  KEXPECT_EQ('x', buf[0]);

  len = 1;
  KEXPECT_EQ(0, getsockname(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(1, len);
  KEXPECT_NE('x', buf[0]);
  KEXPECT_EQ('x', buf[1]);

  len = 1;
  KEXPECT_EQ(0, getpeername(s1, (struct sockaddr*)buf, &len));
  KEXPECT_EQ(1, len);
  KEXPECT_NE('x', buf[0]);
  KEXPECT_EQ('x', buf[1]);

  len = -5;
  KEXPECT_ERRNO(EINVAL, getsockname(s1, (struct sockaddr*)buf, &len));
  KEXPECT_ERRNO(EINVAL, getpeername(s1, (struct sockaddr*)buf, &len));

  // Test bad address.
  len = 200;
  KEXPECT_SIGNAL(SIGSEGV, getsockname(s1, (struct sockaddr*)0x0, &len));
  KEXPECT_SIGNAL(SIGSEGV,
                 getsockname(s1, (struct sockaddr*)INVALID_ADDR, &len));
  KEXPECT_SIGNAL(SIGSEGV, getpeername(s1, (struct sockaddr*)0x0, &len));
  KEXPECT_SIGNAL(SIGSEGV,
                 getpeername(s1, (struct sockaddr*)INVALID_ADDR, &len));
}

static void sockname_tests(void) {
  sockname_unix_tests();
}

void socket_test(void) {
  socket_unix_test();
  sockopt_test();
  sockname_tests();
}
