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
//
// To run this test, run an echo server on the host (outside the VM), e.g.:
//   socat UDP6-RECVFROM:5558,fork,reuseaddr EXEC:cat
//   socat TCP6-LISTEN:5558,fork,reuseaddr EXEC:cat
#include "dev/timer.h"
#include "net/ip/util.h"
#include "test/kernel_tests.h"

#include "common/endian.h"
#include "net/bind.h"
#include "net/socket/socket.h"
#include "net/util.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "proc/sleep.h"
#include "user/include/apos/net/socket/tcp.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define EXTERNAL_PORT 5558
#define EXTERNAL_DST_V4 "10.0.2.2"
#define EXTERNAL_DST_V6 "fec0::2"

static void udp_v4_test(void) {
  KTEST_BEGIN("Network echo test (UDP, IPv4)");
  int sock = net_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = str2inet(EXTERNAL_DST_V4);
  dest.sin_port = btoh16(EXTERNAL_PORT);
  KEXPECT_EQ(0, net_connect(sock, (struct sockaddr*)&dest, sizeof(dest)));
  vfs_make_nonblock(sock);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "abc", 3));
  ksleep(20);
  KEXPECT_EQ(3, vfs_read(sock, buf, 10));
  KEXPECT_STREQ("abc", buf);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "123", 3));
  ksleep(20);
  KEXPECT_EQ(3, vfs_read(sock, buf, 10));
  KEXPECT_STREQ("123", buf);

  KEXPECT_EQ(0, vfs_close(sock));
}

static ssize_t read_loop(int fd, void* buf, size_t len) {
  ssize_t result;
  apos_ms_t start = get_time_ms();
  do {
    result = vfs_read(fd, buf, len);
    if (result == -EAGAIN) {
      ksleep(10);
    }
  } while (result == -EAGAIN && get_time_ms() - start < 100);
  return result;
}

static void udp_v6_test(void) {
  KTEST_BEGIN("Network echo test (UDP, IPv6)");
  int sock = net_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in6 dest;
  dest.sin6_family = AF_INET6;
  KEXPECT_EQ(0, str2inet6(EXTERNAL_DST_V6, &dest.sin6_addr));
  dest.sin6_port = btoh16(EXTERNAL_PORT);
  KEXPECT_EQ(0, net_connect(sock, (struct sockaddr*)&dest, sizeof(dest)));
  vfs_make_nonblock(sock);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "abc", 3));
  KEXPECT_EQ(3, read_loop(sock, buf, 10));
  KEXPECT_STREQ("abc", buf);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "123", 3));
  KEXPECT_EQ(3, read_loop(sock, buf, 10));
  KEXPECT_STREQ("123", buf);

  KEXPECT_EQ(0, vfs_close(sock));
}

static void tcp_v4_test(void) {
  KTEST_BEGIN("Network echo test (TCP, IPv4)");
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = str2inet(EXTERNAL_DST_V4);
  dest.sin_port = btoh16(EXTERNAL_PORT);
  KEXPECT_EQ(0, net_connect(sock, (struct sockaddr*)&dest, sizeof(dest)));
  vfs_make_nonblock(sock);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "abc", 3));
  KEXPECT_EQ(3, read_loop(sock, buf, 10));
  KEXPECT_STREQ("abc", buf);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "123", 3));
  KEXPECT_EQ(3, read_loop(sock, buf, 10));
  KEXPECT_STREQ("123", buf);

  // Do SHUT_RD then send data, which will cause an echo and reset.  This
  // prevents the socket hanging around in TIME_WAIT.
  KEXPECT_EQ(0, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(3, vfs_write(sock, "xyz", 3));
  KEXPECT_EQ(0, vfs_close(sock));
}

static void tcp_v6_test(void) {
  KTEST_BEGIN("Network echo test (TCP, IPv6)");
  int sock = net_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in6 dest;
  dest.sin6_family = AF_INET6;
  KEXPECT_EQ(0, str2inet6(EXTERNAL_DST_V6, &dest.sin6_addr));
  dest.sin6_port = btoh16(EXTERNAL_PORT);
  KEXPECT_EQ(0, net_connect(sock, (struct sockaddr*)&dest, sizeof(dest)));
  vfs_make_nonblock(sock);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "abc", 3));
  ksleep(20);
  KEXPECT_EQ(3, vfs_read(sock, buf, 10));
  KEXPECT_STREQ("abc", buf);

  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, vfs_write(sock, "123", 3));
  ksleep(20);
  KEXPECT_EQ(3, vfs_read(sock, buf, 10));
  KEXPECT_STREQ("123", buf);

  // Do SHUT_RD then send data, which will cause an echo and reset.  This
  // prevents the socket hanging around in TIME_WAIT.
  KEXPECT_EQ(0, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(3, vfs_write(sock, "xyz", 3));
  KEXPECT_EQ(0, vfs_close(sock));
}

static bool wait_for_ipv6(void) {
  apos_ms_t timeout = get_time_ms() + 1500;
  netaddr_t dst;
  dst.family = AF_INET6;
  KEXPECT_EQ(0, str2inet6(EXTERNAL_DST_V6, &dst.a.ip6));
  while (get_time_ms() < timeout) {
    netaddr_t src;
    if (ip_pick_src_netaddr(&dst, &src) == 0) {
      return true;
    }
    ksleep(20);
  }
  return false;
}

void net_echo_test(void) {
  KTEST_SUITE_BEGIN("net echo");

  udp_v4_test();
  tcp_v4_test();

  // Wait for an IPv6 address to be ready.
  KTEST_BEGIN("Network echo test: IPv6 setup");
  KEXPECT_TRUE(wait_for_ipv6());

  udp_v6_test();
  tcp_v6_test();
}
