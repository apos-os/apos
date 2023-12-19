// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#include "common/endian.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "dev/timer.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/inet.h"
#include "net/ip/checksum.h"
#include "net/ip/ip4_hdr.h"
#include "net/socket/socket.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/protocol.h"
#include "net/util.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/tcp.h"
#include "user/include/apos/posix_signal.h"
#include "user/include/apos/time_types.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define TEST_SEQ_START (UINT32_MAX - 102)

// How many different start sequence numbers to run the tests with.  Normally
// will be 1, but crank up to ~20-30 (along with tweaking TEST_SEQ_START) to
// get good coverage of sequence number overflow scenarios.
#define TEST_SEQ_ITERS 1

// How long (in ms) to wait for async operations to confirm they're blocking.
// Increase this to make tests more stringent at the cost of running longer.
#define BLOCK_VERIFY_MS 10

static uint32_t g_seq_start = TEST_SEQ_START;

// Some helpers just to make tests clearer to read and eliminate lots of silly
// casting of sockaddr structs.
static const char* ip2str(in_addr_t addr) {
  static char buf[INET_PRETTY_LEN];
  return inet2str(addr, buf);
}

static const char* sas_ip2str(const struct sockaddr_storage* sas) {
  KASSERT(sas->sa_family == AF_INET);
  return ip2str(((struct sockaddr_in*)sas)->sin_addr.s_addr);
}

static const char* sin2str(const struct sockaddr_in* sin) {
  static char buf[SOCKADDR_PRETTY_LEN];
  KASSERT(sin->sin_family == AF_INET);
  return sockaddr2str((const struct sockaddr*)sin, sizeof(struct sockaddr_in),
                      buf);
}

static void make_saddr(struct sockaddr_in* saddr, const char* addr, int port) {
  saddr->sin_family = AF_INET;
  saddr->sin_addr.s_addr = str2inet(addr);
  saddr->sin_port = htob16(port);
}

static bool has_sigpipe(void) {
  const ksigset_t sigset = proc_pending_signals(proc_current());
  return ksigismember(&sigset, SIGPIPE);
}

static int do_bind(int sock, const char* addr, int port) {
  struct sockaddr_in saddr;
  make_saddr(&saddr, addr, port);
  return net_bind(sock, (struct sockaddr*)&saddr, sizeof(saddr));
}

static int do_connect(int sock, const char* addr, int port) {
  struct sockaddr_in saddr;
  make_saddr(&saddr, addr, port);
  return net_connect(sock, (struct sockaddr*)&saddr, sizeof(saddr));
}

static bool socket_has_data(int fd, int timeout_ms) {
  struct apos_pollfd pfd;
  pfd.events = KPOLLIN;
  pfd.fd = fd;
  int result = vfs_poll(&pfd, 1, timeout_ms);
  KASSERT(result >= 0);
  return (result > 0);
}

static const char* do_read_len(int sock, int len) {
  KASSERT(len < 100);
  static char buf[100];
  // TODO(tcp): call socket_has_data() once poll is supported on TCP sockets.
  int result = vfs_read(sock, buf, len);
  if (KEXPECT_GE(result, 0)) {
    buf[result] = '\0';
  } else {
    ksprintf(buf, "<error: %s>", errorname(-result));
  }
  return buf;
}

static const char* do_read(int sock) { return do_read_len(sock, 99); }

static int set_initial_seqno(int socket, int initial_seq) {
  return net_setsockopt(socket, IPPROTO_TCP, SO_TCP_SEQ_NUM, &initial_seq,
                        sizeof(initial_seq));
}

static int getsockname_inet(int socket, struct sockaddr_in* sin) {
  kmemset(sin, 0xab, sizeof(struct sockaddr_in));
  struct sockaddr_storage sas;
  int result = net_getsockname(socket, (struct sockaddr*)&sas);
  if (result) return result;
  if (sas.sa_family == AF_INET) {
    kmemcpy(sin, &sas, sizeof(struct sockaddr_in));
  }
  return 0;
}

static int getpeername_inet(int socket, struct sockaddr_in* sin) {
  kmemset(sin, 0xab, sizeof(struct sockaddr_in));
  struct sockaddr_storage sas;
  int result = net_getpeername(socket, (struct sockaddr*)&sas);
  if (result) return result;
  if (sas.sa_family == AF_INET) {
    kmemcpy(sin, &sas, sizeof(struct sockaddr_in));
  }
  return 0;
}

static int do_setsockopt_int(int socket, int domain, int option, int val) {
  return net_setsockopt(socket, domain, option, &val, sizeof(int));
}

static const char* get_sock_state(int socket) {
  static char buf[40];
  socklen_t len = 40;
  int result = net_getsockopt(socket, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len);
  KEXPECT_EQ(0, result);
  return buf;
}

static tcp_key_t tcp_key_sin(const struct sockaddr_in* a,
                             const struct sockaddr_in* b) {
  return tcp_key((const struct sockaddr*)a, (const struct sockaddr*)b);
}

static void tcp_key_test(void) {
  KTEST_BEGIN("TCP key test (AF_INET)");
  struct sockaddr_in src1, src2, dst1, dst2;
  kmemset(&src1, 0xaa, sizeof(src1));
  kmemset(&src2, 0xbb, sizeof(src2));
  kmemset(&dst1, 0xcc, sizeof(dst1));
  kmemset(&dst2, 0xdd, sizeof(dst2));
  src1.sin_family = src2.sin_family = dst1.sin_family = dst2.sin_family =
      AF_INET;
  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
  src1.sin_addr.s_addr = str2inet("10.0.1.1");
  src1.sin_port = 1;
  dst1.sin_addr.s_addr = str2inet("10.0.1.2");
  dst1.sin_port = 2;
  src2.sin_addr.s_addr = str2inet("10.0.1.1");
  src2.sin_port = 1;
  dst2.sin_addr.s_addr = str2inet("10.0.1.2");
  dst2.sin_port = 2;
  KEXPECT_EQ(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
  KEXPECT_EQ(tcp_key_sin(&src2, &dst1), tcp_key_sin(&src1, &dst2));
  KEXPECT_EQ(tcp_key_sin(&src1, &dst2), tcp_key_sin(&src2, &dst1));

  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&dst1, &src1));

  src1 = src2;
  src1.sin_port = 2;
  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));
  src1 = src2;
  src1.sin_addr.s_addr = str2inet("10.0.1.2");
  KEXPECT_NE(tcp_key_sin(&src1, &dst1), tcp_key_sin(&src2, &dst2));

  // Test sensitivity to each element of the 5-tuple.
  src2 = src1;
  dst2 = dst1;
  tcp_key_t orig = tcp_key_sin(&src2, &dst2);
  src2.sin_addr.s_addr++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  src2 = src1;

  src2.sin_port++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  src2 = src1;

  dst2.sin_addr.s_addr++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  dst2 = dst1;

  dst2.sin_port++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  dst2 = dst1;
}

static void seqno_test(void) {
  KTEST_BEGIN("TCP: sequence number comparisons test");
  KEXPECT_TRUE(seq_lt(0, 1));
  KEXPECT_TRUE(seq_lt(0, UINT32_MAX / 2 - 1));

  // Cut ties in favor of "less than".
  KEXPECT_TRUE(seq_lt(0, UINT32_MAX / 2));
  KEXPECT_FALSE(seq_lt(0, UINT32_MAX / 2 + 1));
  KEXPECT_FALSE(seq_lt(UINT32_MAX / 2, UINT32_MAX));
  KEXPECT_TRUE(seq_lt(UINT32_MAX / 2 + 1, UINT32_MAX));
  KEXPECT_FALSE(seq_lt(UINT32_MAX / 2 - 1, UINT32_MAX));
  KEXPECT_TRUE(seq_lt(UINT32_MAX - 1, UINT32_MAX));
  KEXPECT_TRUE(seq_lt(UINT32_MAX / 2 - 1, UINT32_MAX / 2));
  KEXPECT_TRUE(seq_lt(UINT32_MAX / 2, UINT32_MAX / 2 + 1));
  KEXPECT_TRUE(seq_lt(UINT32_MAX, 0));
  KEXPECT_TRUE(seq_lt(UINT32_MAX, 1));
  KEXPECT_TRUE(seq_lt(UINT32_MAX - 1, 1));
  KEXPECT_TRUE(seq_lt(UINT32_MAX / 2 + 2, 0));
  KEXPECT_FALSE(seq_lt(0, 0));
  KEXPECT_FALSE(seq_lt(UINT32_MAX, UINT32_MAX));
  KEXPECT_FALSE(seq_lt(UINT32_MAX / 2, UINT32_MAX / 2));
  KEXPECT_FALSE(seq_lt(1, 0));
  KEXPECT_FALSE(seq_lt(UINT32_MAX / 2 - 1, 0));
  KEXPECT_FALSE(seq_lt(UINT32_MAX / 2, 0));
  KEXPECT_TRUE(seq_lt(UINT32_MAX / 2 + 1, 0));

  KEXPECT_TRUE(seq_lt(UINT32_MAX / 2 + 2, 0));

  // Ensure consistent relationships between all comparisons.
  const uint32_t kNumsToCompare[] = {0,
                                     1,
                                     2,
                                     UINT32_MAX / 4 - 1,
                                     UINT32_MAX / 4,
                                     UINT32_MAX / 4 + 1,
                                     UINT32_MAX / 2 - 2,
                                     UINT32_MAX / 2 - 1,
                                     UINT32_MAX / 2,
                                     UINT32_MAX / 2 + 1,
                                     UINT32_MAX / 2 + 2,
                                     UINT32_MAX - 2,
                                     UINT32_MAX - 1,
                                     UINT32_MAX};
  const size_t kNumNums = sizeof(kNumsToCompare) / sizeof(uint32_t);
  for (size_t i = 0; i < kNumNums; ++i) {
    uint32_t a = kNumsToCompare[i];
    KEXPECT_TRUE(seq_lt(a, a + 1));
    KEXPECT_TRUE(seq_lt(a - 1, a));
    KEXPECT_TRUE(seq_gt(a + 1, a));
    KEXPECT_TRUE(seq_gt(a, a - 1));

    for (size_t j = 0; j < kNumNums; ++j) {
      uint32_t b = kNumsToCompare[j];
      bool v = true;
      if (a == b) {
        v &= KEXPECT_TRUE(seq_le(a, b));
        v &= KEXPECT_TRUE(seq_le(b, a));
        v &= KEXPECT_TRUE(seq_ge(a, b));
        v &= KEXPECT_TRUE(seq_ge(b, a));
        v &= KEXPECT_FALSE(seq_lt(a, b));
        v &= KEXPECT_FALSE(seq_lt(b, a));
        v &= KEXPECT_FALSE(seq_gt(a, b));
        v &= KEXPECT_FALSE(seq_gt(b, a));
      } else if (seq_lt(a, b)) {
        v &= KEXPECT_TRUE(seq_lt(a, b));
        v &= KEXPECT_TRUE(seq_le(a, b));
        v &= KEXPECT_FALSE(seq_gt(a, b));
        v &= KEXPECT_FALSE(seq_ge(a, b));
        v &= KEXPECT_FALSE(seq_lt(b, a));
        v &= KEXPECT_FALSE(seq_le(b, a));
        v &= KEXPECT_TRUE(seq_gt(b, a));
        v &= KEXPECT_TRUE(seq_ge(b, a));
      } else {
        v &= KEXPECT_FALSE(seq_lt(a, b));
        v &= KEXPECT_FALSE(seq_le(a, b));
        v &= KEXPECT_TRUE(seq_gt(a, b));
        v &= KEXPECT_TRUE(seq_ge(a, b));
        v &= KEXPECT_TRUE(seq_lt(b, a));
        v &= KEXPECT_TRUE(seq_le(b, a));
        v &= KEXPECT_FALSE(seq_gt(b, a));
        v &= KEXPECT_FALSE(seq_ge(b, a));
      }
      if (!v) {
        klogf("seqno test failed: a = %u, b = %u\n", a, b);
      }
    }
  }
}

static void tcp_socket_test(void) {
  KTEST_BEGIN("Basic TCP socket creation");
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("Basic TCP socket creation (default protocol)");
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("Basic TCP socket creation (bad protocol)");
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, 1000));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, -1));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, IPPROTO_UDP));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_INET, SOCK_STREAM, IPPROTO_ICMP));
}

static void sockopt_test(void) {
  KTEST_BEGIN("TCP socket: getsockopt");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  int val[2];
  socklen_t vallen = sizeof(int) * 2;
  KEXPECT_EQ(0, net_getsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(SOCK_STREAM, val[0]);

  KEXPECT_EQ(-ENOPROTOOPT,
             net_getsockopt(sock, SOL_SOCKET, 10, &val[0], &vallen));

  char buf[40];
  socklen_t len = 40;
  KEXPECT_EQ(0, net_getsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len));
  KEXPECT_EQ(7, len);
  KEXPECT_STREQ("CLOSED", buf);
  kmemset(buf, 0, 10);
  len = 7;
  KEXPECT_EQ(0, net_getsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len));
  KEXPECT_EQ(7, len);
  KEXPECT_STREQ("CLOSED", buf);

  kstrcpy(buf, "xyz");
  len = 6;
  KEXPECT_EQ(-ENOBUFS,
             net_getsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len));
  KEXPECT_EQ(6, len);

  len = 1;
  KEXPECT_EQ(-ENOBUFS,
             net_getsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len));
  KEXPECT_EQ(1, len);

  len = 0;
  KEXPECT_EQ(-ENOBUFS,
             net_getsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len));
  KEXPECT_EQ(0, len);

  len = -1;
  KEXPECT_EQ(-ENOBUFS,
             net_getsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len));
  KEXPECT_EQ(-1, len);

  KEXPECT_STREQ("xyz", buf);

  KEXPECT_EQ(-EINVAL,
             net_setsockopt(sock, IPPROTO_TCP, SO_TCP_SOCKSTATE, "abc", 3));

  KTEST_BEGIN("TCP socket: setsockopt");
  KEXPECT_EQ(-ENOPROTOOPT,
             net_setsockopt(sock, SOL_SOCKET, SO_TYPE, &val[0], vallen));

  KEXPECT_EQ(0, vfs_close(sock));
}

static void bind_test(void) {
  KTEST_BEGIN("getsockname(SOCK_STREAM): unbound socket");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(INADDR_ANY, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(INET_PORT_ANY, result_addr->sin_port);

  KTEST_BEGIN("getpeername(SOCK_STREAM): unbound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));


  KTEST_BEGIN("bind(SOCK_STREAM): can bind to NIC's address");
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_port = 1234;

  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("getsockname(SOCK_STREAM): bound socket");
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(addr.sin_addr.s_addr, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(1234, result_addr->sin_port);

  KTEST_BEGIN("getpeername(SOCK_STREAM): bound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(sock, (struct sockaddr*)&result_addr_storage));

  KTEST_BEGIN("bind(SOCK_STREAM): already bound socket");
  KEXPECT_EQ(-EINVAL, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock));


  KTEST_BEGIN("bind(SOCK_STREAM): bind to bad address");
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  addr.sin_addr.s_addr = str2inet("0.0.0.1");
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  addr.sin_addr.s_addr = str2inet("8.8.8.8");
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  // Too-short address.
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  KEXPECT_EQ(-EADDRNOTAVAIL,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr) - 5));


  KTEST_BEGIN("bind(SOCK_STREAM): wrong address family");
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_family = AF_UNIX;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));


  KTEST_BEGIN("bind(SOCK_STREAM): bad FD");
  addr.sin_family = AF_UNIX;
  addr.sin_addr.s_addr = str2inet("0.0.0.0");
  KEXPECT_EQ(-EBADF, net_bind(100, (struct sockaddr*)&addr, sizeof(addr)));

  vfs_close(sock);
}

static void multi_bind_test(void) {
  KTEST_BEGIN("bind(SOCK_STREAM): bind to already-bound address");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  addr.sin_port = 1234;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  int sock2 = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock2, 0);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_STREAM): bind to INADDR_ANY on already-used port");
  addr.sin_addr.s_addr = INADDR_ANY;
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN(
      "bind(SOCK_STREAM): can bind to previously-used port after close");
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock2));
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  sock2 = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock2, 0);

  KTEST_BEGIN(
      "bind(SOCK_STREAM): bind to addr on already-used INADDR_ANY port");
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 1234;
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_STREAM): bind to port 0 (specific IP)");
  addr.sin_addr.s_addr = str2inet("127.0.0.1");
  addr.sin_port = 0;
  KEXPECT_EQ(0, vfs_close(sock));
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  struct sockaddr_storage sockname_addr;
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&sockname_addr));
  KEXPECT_STREQ("127.0.0.1", sas_ip2str(&sockname_addr));
  in_port_t port1 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port1);

  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, net_getsockname(sock2, (struct sockaddr*)&sockname_addr));
  KEXPECT_STREQ("127.0.0.1", sas_ip2str(&sockname_addr));
  in_port_t port2 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port2);
  KEXPECT_NE(port1, port2);

  // TODO(aoates): test binding to the same port on two different addresses.

  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_close(sock2));
}

#define RAW_RECV_BUF_SIZE 100
#define DEFAULT_WNDSIZE 8000

typedef struct {
  kthread_t thread;
  int socket;
  int op_result;
  notification_t op_started;
  notification_t op_done;

  // Address of the TCP socket under test.
  const char* tcp_addr_str;
  struct sockaddr_in tcp_addr;

  // Raw socket and buffer for the "other side".
  const char* raw_addr_str;
  struct sockaddr_in raw_addr;
  int raw_socket;
  char recv[RAW_RECV_BUF_SIZE];

  const char* arg_addr;
  int arg_port;
  void* arg_buffer;
  size_t arg_buflen;

  // Window size to send when not otherwise specified.
  size_t wndsize;

  // Sequence base for the socket.
  uint32_t seq_base;
  uint32_t send_seq_base;
} tcp_test_state_t;

// Creates and initializes the test state.  Does _not_ bind the test socket.
// Multiple test states may be used in the same test simultaneously to test
// different sockets simultaneously --- the raw recv sockets should each bind to
// a different IP, however, or each will get packets sent by all test sockets.
static void init_tcp_test(tcp_test_state_t* s, const char* tcp_addr,
                          int tcp_port, const char* dst_addr, int dst_port) {
  s->wndsize = DEFAULT_WNDSIZE;
  s->seq_base = g_seq_start;
  s->send_seq_base = g_seq_start + 100 - 500;
  s->socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(s->socket, 0);

  KEXPECT_EQ(0, set_initial_seqno(s->socket, s->seq_base + 100));

  s->tcp_addr_str = tcp_addr;
  make_saddr(&s->tcp_addr, tcp_addr, tcp_port);

  // Create the raw socket that will converse with the TCP socket under test.
  s->raw_socket = net_socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  KEXPECT_GE(s->raw_socket, 0);

  s->raw_addr_str = dst_addr;
  make_saddr(&s->raw_addr, dst_addr, dst_port);
  KEXPECT_EQ(0, net_bind(s->raw_socket, (struct sockaddr*)&s->raw_addr,
                         sizeof(s->raw_addr)));
}

static void cleanup_tcp_test(tcp_test_state_t* s) {
  if (s->socket >= 0) {
    KEXPECT_EQ(0, vfs_close(s->socket));
  }
  KEXPECT_EQ(0, vfs_close(s->raw_socket));
}

static void* tcp_thread_connect(void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  ntfn_notify(&s->op_started);
  s->op_result = do_connect(s->socket, s->arg_addr, s->arg_port);
  ntfn_notify(&s->op_done);
  return NULL;
}

// Start an async connect() call in another thread and ensure it blocks.  The
// test should either manually finish the connect call (with the SYN/SYN-ACK/ACK
// sequence, or a variant), or call finish_standard_connect() below.
static bool start_connect(tcp_test_state_t* s, const char* ip, int port) {
  ntfn_init(&s->op_started);
  ntfn_init(&s->op_done);
  s->arg_addr = ip;
  s->arg_port = port;
  KEXPECT_EQ(0, proc_thread_create(&s->thread, &tcp_thread_connect, s));
  if (!ntfn_await_with_timeout(&s->op_started, 5000)) {
    KTEST_ADD_FAILURE("connect() thread didn't start");
    return false;
  }
  if (ntfn_await_with_timeout(&s->op_done, BLOCK_VERIFY_MS)) {
    KTEST_ADD_FAILURE("connect() finished without blocking");
    KEXPECT_EQ(0, s->op_result);  // Get the error code.
    return false;
  }
  return true;
}

static void* tcp_thread_read(void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  ntfn_notify(&s->op_started);
  s->op_result = vfs_read(s->socket, s->arg_buffer,s->arg_buflen);
  ntfn_notify(&s->op_done);
  return NULL;
}

// Start an async read() call in another thread and ensure it blocks.
static bool start_read(tcp_test_state_t* s, void* buf, size_t buflen) {
  kmemset(buf, 0, buflen);
  ntfn_init(&s->op_started);
  ntfn_init(&s->op_done);
  s->arg_buffer = buf;
  s->arg_buflen = buflen;
  KEXPECT_EQ(0, proc_thread_create(&s->thread, &tcp_thread_read, s));
  if (!ntfn_await_with_timeout(&s->op_started, 5000)) {
    KTEST_ADD_FAILURE("read() thread didn't start");
    return false;
  }
  if (ntfn_await_with_timeout(&s->op_done, BLOCK_VERIFY_MS)) {
    KTEST_ADD_FAILURE("read() finished without blocking");
    KEXPECT_EQ(0, s->op_result);  // Get the error code.
    return false;
  }
  return true;
}

static void* tcp_thread_write(void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  ntfn_notify(&s->op_started);
  s->op_result = vfs_write(s->socket, s->arg_buffer, s->arg_buflen);
  ntfn_notify(&s->op_done);
  return NULL;
}

// Start an async write() call in another thread and ensure it blocks.
static bool start_write(tcp_test_state_t* s, const char* data) {
  ntfn_init(&s->op_started);
  ntfn_init(&s->op_done);
  s->arg_buffer = (void*)data;
  s->arg_buflen = kstrlen(data);
  KEXPECT_EQ(0, proc_thread_create(&s->thread, &tcp_thread_write, s));
  if (!ntfn_await_with_timeout(&s->op_started, 5000)) {
    KTEST_ADD_FAILURE("write() thread didn't start");
    return false;
  }
  if (ntfn_await_with_timeout(&s->op_done, BLOCK_VERIFY_MS)) {
    KTEST_ADD_FAILURE("write() finished without blocking");
    KEXPECT_EQ(0, s->op_result);  // Get the error code.
    return false;
  }
  return true;
}

static int finish_op(tcp_test_state_t* s) {
  bool finished = ntfn_await_with_timeout(&s->op_done, 5000);
  KEXPECT_EQ(true, finished);
  if (!finished) return -ETIMEDOUT;

  KEXPECT_EQ(NULL, kthread_join(s->thread));
  s->thread = NULL;
  return s->op_result;
}

static bool raw_has_packets_wait(tcp_test_state_t* s, int timeout_ms) {
  return socket_has_data(s->raw_socket, timeout_ms);
}

static bool raw_has_packets(tcp_test_state_t* s) {
  return raw_has_packets_wait(s, 0);
}

static ssize_t do_raw_recv(tcp_test_state_t* s) {
  if (!raw_has_packets(s)) {
    KTEST_ADD_FAILURE("Raw socket has no packets available");
    return -EAGAIN;
  }
  kmemset(s->recv, 0, RAW_RECV_BUF_SIZE);
  return net_recvfrom(s->raw_socket, s->recv, RAW_RECV_BUF_SIZE - 1, 0, NULL,
                      NULL);
}

static ssize_t do_raw_send(tcp_test_state_t* s, const void* buf, size_t len) {
  return net_sendto(s->raw_socket, buf, len, 0, (struct sockaddr*)&s->tcp_addr,
                    sizeof(s->tcp_addr));
}

// Special value to indicate a zero window size (since passing zero means
// "ignore").
#define WNDSIZE_ZERO 0xabcd

// Specification for a packet to expect or send.  Fields not supplied are not
// checked (on receive), or given default values (on send).
typedef struct {
  int flags;
  uint32_t seq;
  uint32_t ack;
  int wndsize;
  const char* data;
  size_t datalen;
} test_packet_spec_t;

static test_packet_spec_t SYN_PKT(int seq, int wndsize) {
  return ((test_packet_spec_t){
      .flags = TCP_FLAG_SYN, .seq = seq, .wndsize = wndsize});
}

static test_packet_spec_t SYNACK_PKT(int seq, int ack, int wndsize) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_SYN | TCP_FLAG_ACK,
                               .seq = seq,
                               .ack = ack,
                               .wndsize = wndsize});
}

static test_packet_spec_t ACK_PKT(int seq, int ack) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_ACK, .seq = seq, .ack = ack});
}

static test_packet_spec_t ACK_PKT2(int seq, int ack, int wndsize) {
  return ((test_packet_spec_t){
      .flags = TCP_FLAG_ACK, .seq = seq, .ack = ack, .wndsize = wndsize});
}

static test_packet_spec_t FIN_PKT(int seq, int ack) {
  return ((test_packet_spec_t){
      .flags = TCP_FLAG_FIN | TCP_FLAG_ACK, .seq = seq, .ack = ack});
}

static test_packet_spec_t FIN_PKT2(int seq, int ack, int wndsize) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_FIN | TCP_FLAG_ACK,
                               .seq = seq,
                               .ack = ack,
                               .wndsize = wndsize});
}

static test_packet_spec_t RST_PKT(int seq, int ack) {
  return ((test_packet_spec_t){
      .flags = TCP_FLAG_RST | TCP_FLAG_ACK, .seq = seq, .ack = ack});
}

static test_packet_spec_t RST_NOACK_PKT(int seq) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_RST, .seq = seq});
}

static test_packet_spec_t DATA_PKT(int seq, int ack, const char* data) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_ACK,
                               .seq = seq,
                               .ack = ack,
                               .data = data,
                               .datalen = kstrlen(data)});
}

static test_packet_spec_t DATA_FIN_PKT(int seq, int ack, const char* data) {
  test_packet_spec_t result = DATA_PKT(seq, ack, data);
  result.flags |= TCP_FLAG_FIN;
  return result;
}

#define EXPECT_PKT(_state, _spec) KEXPECT_TRUE(receive_pkt(_state, _spec))
#define SEND_PKT(_state, _spec) KEXPECT_TRUE(send_pkt(_state, _spec))

// Expects to receive a packet matching the given description, returning true if
// it does.
static bool receive_pkt(tcp_test_state_t* s, test_packet_spec_t spec) {
  bool v = true;
  v &= KEXPECT_TRUE(raw_has_packets(s));
  if (!v) return v;

  int result = do_raw_recv(s);
  v &= KEXPECT_GE(result, 0);
  if (!v) return v;

  // Validate the IP header.
  v &= KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t) + spec.datalen, result);
  if (result < (int)sizeof(ip4_hdr_t) + (int)sizeof(tcp_hdr_t)) {
    return false;
  }

  ip4_hdr_t* ip_hdr = (ip4_hdr_t*)s->recv;
  v &= KEXPECT_EQ(0x45, ip_hdr->version_ihl);
  v &= KEXPECT_EQ(0x0, ip_hdr->dscp_ecn);
  v &= KEXPECT_EQ(result, btoh16(ip_hdr->total_len));
  v &= KEXPECT_EQ(0, ip_hdr->id);
  v &= KEXPECT_EQ(0, ip_hdr->flags_fragoff);
  v &= KEXPECT_GE(ip_hdr->ttl, 10);
  v &= KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  // Don't bother checking the checksum here.
  v &= KEXPECT_STREQ(s->tcp_addr_str, ip2str(ip_hdr->src_addr));
  v &= KEXPECT_STREQ(s->raw_addr_str, ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)&s->recv[sizeof(ip4_hdr_t)];
  v &= KEXPECT_EQ(btoh16(s->tcp_addr.sin_port), btoh16(tcp_hdr->src_port));
  v &= KEXPECT_EQ(btoh16(s->raw_addr.sin_port), btoh16(tcp_hdr->dst_port));
  if (spec.seq != 0) {
    v &= KEXPECT_EQ(spec.seq, btoh32(tcp_hdr->seq) - s->seq_base);
  }
  if (spec.ack != 0) {
    v &= KEXPECT_EQ(spec.ack, btoh32(tcp_hdr->ack) - s->send_seq_base);
  }
  v &= KEXPECT_EQ(0, tcp_hdr->_zeroes);
  v &= KEXPECT_EQ(5, tcp_hdr->data_offset);
  v &= KEXPECT_EQ(spec.flags, tcp_hdr->flags);
  if (btoh16(tcp_hdr->wndsize) == 0 && spec.wndsize == 0) {
    KTEST_ADD_FAILURE("Must use WNDSIZE_ZERO when receiving a zero wndsize");
    v = false;
  }
  if (spec.wndsize != 0) {
    v &= KEXPECT_EQ(spec.wndsize == WNDSIZE_ZERO ? 0 : spec.wndsize,
                        btoh16(tcp_hdr->wndsize));
  }
  // Don't bother checking this checksum either.
  v &= KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // Check data.
  if (spec.data) {
    KEXPECT_STREQ(spec.data, s->recv + sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t));
  }
  return v;
}

// Builds a packet based on the given spec and sends it.
static bool send_pkt(tcp_test_state_t* s, test_packet_spec_t spec) {
  ip4_pseudo_hdr_t pseudo_ip;

  size_t tcp_len = sizeof(tcp_hdr_t) + spec.datalen;
  pseudo_ip.src_addr = s->raw_addr.sin_addr.s_addr;
  pseudo_ip.dst_addr = s->tcp_addr.sin_addr.s_addr;
  pseudo_ip.zeroes = 0;
  pseudo_ip.protocol = IPPROTO_TCP;
  pseudo_ip.length = btoh16(tcp_len);

  void* buf = kmalloc(tcp_len);
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)buf;
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port = s->raw_addr.sin_port;
  tcp_hdr->dst_port = s->tcp_addr.sin_port;
  tcp_hdr->seq = btoh32(s->send_seq_base + spec.seq);
  tcp_hdr->ack =
      (spec.flags & TCP_FLAG_ACK) ? btoh32(s->seq_base + spec.ack) : 0;
  tcp_hdr->data_offset = 5;
  tcp_hdr->flags = spec.flags;
  if (spec.wndsize == 0) spec.wndsize = s->wndsize;
  else if (spec.wndsize == WNDSIZE_ZERO) spec.wndsize = 0;
  tcp_hdr->wndsize = btoh16(spec.wndsize);
  tcp_hdr->checksum = 0;
  if (spec.datalen > 0) {
    kmemcpy(buf + sizeof(tcp_hdr_t), spec.data, spec.datalen);
  }

  tcp_hdr->checksum =
      ip_checksum2(&pseudo_ip, sizeof(pseudo_ip), tcp_hdr, tcp_len);
  bool result = KEXPECT_EQ(tcp_len, do_raw_send(s, tcp_hdr, tcp_len));
  kfree(buf);
  return result;
}

// Standard operations for tests that don't care about specifics.

// Finish an async connect() call started with start_connect().
static bool finish_standard_connect(tcp_test_state_t* s) {
  bool v = true;
  v &= EXPECT_PKT(s, SYN_PKT(/* seq */ 100, /* wndsize */ 0));
  v &= SEND_PKT(
      s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ s->wndsize));
  v &= EXPECT_PKT(s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  v &= KEXPECT_EQ(0, finish_op(s));  // connect() should complete successfully.
  return v;
}

// Do a standard remote-triggered "connection closed" sequence.  Must pass the
// amount of data send and received on the socket during the course of the test.
static bool do_standard_finish(tcp_test_state_t* s, ssize_t data_sent,
                               ssize_t data_received) {
  bool v = true;
  uint32_t sock_seq = 101 + data_sent;
  uint32_t remote_seq = 501 + data_received;

  // Send FIN to start connection close.
  v &= SEND_PKT(s, FIN_PKT(/* seq */ remote_seq, /* ack */ sock_seq));

  // Should get an ACK.
  v &= EXPECT_PKT(s, ACK_PKT(/* seq */ sock_seq, /* ack */ remote_seq + 1));
  v &= KEXPECT_FALSE(raw_has_packets(s));

  // Shutdown the connection from this side.
  v &= KEXPECT_EQ(0, net_shutdown(s->socket, SHUT_WR));

  // Should get a FIN.
  v &= EXPECT_PKT(s, FIN_PKT(/* seq */ sock_seq, /* ack */ remote_seq + 1));
  v &= SEND_PKT(s, ACK_PKT(remote_seq + 1, /* ack */ sock_seq + 1));
  return v;
}

static void basic_connect_test(void) {
  KTEST_BEGIN("TCP: basic connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.2", 0x5678);
  s.seq_base = s.send_seq_base = 0;
  KEXPECT_EQ(0, set_initial_seqno(s.socket, 100));
  KEXPECT_STREQ("CLOSED", get_sock_state(s.socket));

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 0x5678));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Should have received a SYN.
  int result = do_raw_recv(&s);

  // Validate the IP header.
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  ip4_hdr_t* ip_hdr = (ip4_hdr_t*)s.recv;
  KEXPECT_EQ(0x45, ip_hdr->version_ihl);
  KEXPECT_EQ(0x0, ip_hdr->dscp_ecn);
  KEXPECT_EQ(result, btoh16(ip_hdr->total_len));
  KEXPECT_EQ(0, ip_hdr->id);
  KEXPECT_EQ(0, ip_hdr->flags_fragoff);
  KEXPECT_GE(ip_hdr->ttl, 10);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_EQ(0x7ccd, btoh16(ip_hdr->hdr_checksum));
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ("127.0.0.2", ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)&s.recv[sizeof(ip4_hdr_t)];
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(100, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_SYN, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0x08cf, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // Send SYN-ACK back.  Raw socket will make the IP header for us.
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1000);
  tcp_hdr->ack = btoh32(101);
  tcp_hdr->checksum = 0x7e19;
  tcp_hdr->flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
  tcp_hdr->wndsize = btoh16(8000);
  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Should get an ACK.
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ("127.0.0.2", ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1001, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf8be, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send a FIN.
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1001);
  tcp_hdr->ack = btoh32(101);
  tcp_hdr->data_offset = 5;
  tcp_hdr->flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
  tcp_hdr->wndsize = 8000;
  tcp_hdr->checksum = 0x9ef8;

  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  KEXPECT_TRUE(raw_has_packets(&s));
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_STREQ("127.0.0.1", ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ("127.0.0.2", ip2str(ip_hdr->dst_addr));

  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1002, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf8bd, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // TODO(tcp): verify that read() returns 0/EOF.

  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));

  // Should get a FIN.
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1002, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_FIN | TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf8bc, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // Send final ack.
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1002);
  tcp_hdr->ack = btoh32(102);
  tcp_hdr->data_offset = 5;
  tcp_hdr->flags = TCP_FLAG_ACK;
  tcp_hdr->wndsize = 8000;
  tcp_hdr->checksum = 0x9df8;
  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // TODO(tcp): test other operations on the socket now that its closed.

  cleanup_tcp_test(&s);
}

static void basic_connect_test2(void) {
  KTEST_BEGIN("TCP: basic connect() (v2)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void connect_rst_test(void) {
  KTEST_BEGIN("TCP: RST during connect() (connection refused)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.5", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.5", 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNREFUSED, finish_op(&s));

  // TODO(tcp): test other methods (read, write, etc) in the error state.
  struct sockaddr_storage unused;
  KEXPECT_EQ(-EINVAL, net_getsockname(s.socket, (struct sockaddr*)&unused));
  KEXPECT_EQ(-EINVAL, net_getpeername(s.socket, (struct sockaddr*)&unused));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, "127.0.0.1", 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, "127.0.0.5", 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.1", 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.5", 80));

  // TODO(tcp): if SO_ERROR is implemented, test here as well.

  cleanup_tcp_test(&s);
}

static void multiple_connect_test(void) {
  KTEST_BEGIN("TCP: multiple connect() calls");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.2", 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 0x5678));

  // Try connect() while another thread is blocked in connect().
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, "127.0.0.2", 0x5678));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, "127.0.0.2", 55));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, "127.0.0.1", 55));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, "127.0.0.5", 55));

  KEXPECT_TRUE(finish_standard_connect(&s));

  // Try connect() on a connected socket.
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, "127.0.0.2", 0x5678));
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, "127.0.0.2", 55));
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, "127.0.0.5", 55));

  // Finish up.
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void two_simultaneous_connects_test(void) {
  KTEST_BEGIN("TCP: two sockets connecting simultaneously");
  tcp_test_state_t s1, s2;
  init_tcp_test(&s1, "127.0.0.1", 0x1234, "127.0.0.2", 0x5678);
  init_tcp_test(&s2, "127.0.0.1", 0x1234, "127.0.0.3", 0x5678);
  KEXPECT_EQ(0, set_initial_seqno(s2.socket, s2.seq_base + 700));

  KEXPECT_EQ(0, do_bind(s1.socket, "127.0.0.1", 0x1234));

  // While we're here, validate binding another socket after the first one
  // rebinds as well.  Currently we should not be able to bind to
  // 127.0.0.1:0x1234 because s1 is using it --- but once s1 connects, we should
  // be able to.  Arguably, s2 shouldn't be allowed to until s1's connect
  // _completes_, rather than starts, but this is valid behavior IMO and simpler
  // to implement.  Whether s1's connect() succeeds (in connected sockets map)
  // or fails (state invalid, unbound), s2 bind to the same local address is OK.
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2.socket, "0.0.0.0", 0x1234));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s1, "127.0.0.2", 0x5678));
  KEXPECT_EQ(0, do_bind(s2.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s2, "127.0.0.3", 0x5678));

  // Do SYN, SYN-ACK, ACK for both sockets, interleaved.
  EXPECT_PKT(&s2, SYN_PKT(/* seq */ 700, /* wndsize */ 0));
  SEND_PKT(&s2, SYNACK_PKT(/* seq */ 800, /* ack */ 701, /* wndsize */ 8000));
  EXPECT_PKT(&s1, SYN_PKT(/* seq */ 100, /* wndsize */ 0));
  SEND_PKT(&s1, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s1, ACK_PKT(/* seq */ 101, /* ack */ 501));
  EXPECT_PKT(&s2, ACK_PKT(/* seq */ 701, /* ack */ 801));

  // connect() should complete successfully.
  KEXPECT_EQ(0, finish_op(&s1));
  KEXPECT_EQ(0, finish_op(&s2));

  // TODO(tcp): exchange data.

  // Close each connection.
  SEND_PKT(&s1, FIN_PKT(/* seq */ 501, /* ack */ 101));
  SEND_PKT(&s2, FIN_PKT(/* seq */ 801, /* ack */ 701));
  EXPECT_PKT(&s1, ACK_PKT(/* seq */ 101, /* ack */ 502));
  EXPECT_PKT(&s2, ACK_PKT(/* seq */ 701, /* ack */ 802));
  KEXPECT_EQ(0, net_shutdown(s1.socket, SHUT_WR));
  KEXPECT_EQ(0, net_shutdown(s2.socket, SHUT_WR));

  EXPECT_PKT(&s1, FIN_PKT(/* seq */ 101, /* ack */ 502));
  EXPECT_PKT(&s2, FIN_PKT(/* seq */ 701, /* ack */ 802));
  SEND_PKT(&s1, ACK_PKT(502, /* ack */ 102));
  SEND_PKT(&s2, ACK_PKT(802, /* ack */ 702));

  cleanup_tcp_test(&s1);
  cleanup_tcp_test(&s2);
}

static void rebind_tests(void) {
  KTEST_BEGIN("TCP: cannot rebind a bound socket");
  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "0.0.0.0", 0));

  // See what port it chose.
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_NE(0, result_addr->sin_port);
  in_port_t bound_port = result_addr->sin_port;

  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 100));

  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(bound_port, result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));


  sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 0));

  // See what port it chose.
  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_NE(0, result_addr->sin_port);
  bound_port = result_addr->sin_port;

  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.2", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.2", 100));

  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(bound_port, result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));


  sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 200));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 200));

  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(btoh16(100), result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));


  sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "127.0.0.1", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "127.0.0.1", 200));

  KEXPECT_EQ(0, net_getsockname(sock, (struct sockaddr*)&result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(btoh16(100), result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));
}

static void implicit_bind_test(void) {
  KTEST_BEGIN("TCP: socket implicitly binds on connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0 /* will be chosen later */, "127.0.0.2",
                0x5678);

  // No bind!
  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 0x5678));

  // Find out what we bound to.  getsockname() _during_ connect() is allowed by
  // the spec to do this.
  struct sockaddr_in bound_addr;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_NE(0, bound_addr.sin_port);

  s.tcp_addr = bound_addr;

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(s.tcp_addr.sin_port, bound_addr.sin_port);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);


  KTEST_BEGIN("TCP: socket implicitly rebinds any-addr+any-port on connect()");
  init_tcp_test(&s, "127.0.0.1", 0 /* will be chosen later */, "127.0.0.2",
                0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "0.0.0.0", 0));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 0x5678));

  // As above, find out what port was chosen.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_NE(0, bound_addr.sin_port);
  s.tcp_addr = bound_addr;

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(s.tcp_addr.sin_port, bound_addr.sin_port);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);


  // Internally this is the same as the above, since ports are picked in bind()
  // not connect(), but test for completeness.
  KTEST_BEGIN("TCP: socket implicitly rebinds $IP+any-port on connect()");
  init_tcp_test(&s, "127.0.0.3", 0 /* will be chosen later */, "127.0.0.2",
                0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.3", 0));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 0x5678));

  // As above, find out what port was chosen.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.3", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_NE(0, bound_addr.sin_port);
  s.tcp_addr = bound_addr;

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.3", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(s.tcp_addr.sin_port, bound_addr.sin_port);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);


  // Also redundant with the any-ip/any-port, but included for completeness.
  KTEST_BEGIN("TCP: socket implicitly rebinds any-ip+$PORT on connect()");
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.2", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "0.0.0.0", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 0x5678));

  // Check that the rebind happened correctly.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(0x1234, btoh16(bound_addr.sin_port));

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(0x1234, btoh16(bound_addr.sin_port));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);
}

static void get_addrs_during_connect_test(void) {
  KTEST_BEGIN("TCP: getsockname()/getpeername() during connect()/close()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 3456, "127.0.0.2", 7890);

  struct sockaddr_in addr;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("0.0.0.0:0", sin2str(&addr));
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &addr));

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 3456));
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.1:3456", sin2str(&addr));
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &addr));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.2", 7890));
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.1:3456", sin2str(&addr));
  // We should not be able to get the peer name until the connect finishes.
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &addr));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.1:3456", sin2str(&addr));
  KEXPECT_EQ(0, getpeername_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.2:7890", sin2str(&addr));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // The socket is still considered connected (partially).
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.1:3456", sin2str(&addr));
  KEXPECT_EQ(0, getpeername_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.2:7890", sin2str(&addr));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Arguably this shouldn't return an address anymore, but on macos it does and
  // the implementation is simpler so /shruggie.  -EINVAL would be OK.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("127.0.0.1:3456", sin2str(&addr));
  KEXPECT_EQ(-EINVAL, getpeername_inet(s.socket, &addr));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 102));

  cleanup_tcp_test(&s);

  // TODO(tcp): test the other shutdown path (local close first) once
  // implemented.
}

static void connect_interrupted_test(void) {
  KTEST_BEGIN("TCP: connect() interrupted");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  // ...but the connect should still complete.
  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // Should be able to pass data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void connect_timeout_test(void) {
  KTEST_BEGIN("TCP: connect() timeout");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  struct apos_timeval tv = {9999, 9999};
  socklen_t slen = sizeof(struct apos_timeval);
  KEXPECT_EQ(0,
             net_getsockopt(s.socket, SOL_SOCKET, SO_CONNECTTIMEO, &tv, &slen));
  KEXPECT_EQ(60, tv.tv_sec);
  KEXPECT_EQ(0, tv.tv_usec);

  // Test actual timeout.
  tv.tv_sec = 0;
  tv.tv_usec = 50 * 1000;
  KEXPECT_EQ(0, net_setsockopt(s.socket, SOL_SOCKET, SO_CONNECTTIMEO, &tv,
                               sizeof(tv)));

  apos_ms_t start = get_time_ms();
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_EQ(-ETIMEDOUT, finish_op(&s));
  apos_ms_t end = get_time_ms();
  KEXPECT_GE(end - start, 50);
  KEXPECT_LE(end - start, 500);

  // ...but the connect should still complete.
  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // Should be able to pass data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void connect_gets_to_close_wait_test(void) {
  KTEST_BEGIN("TCP: connect() (socket gets to CLOSE_WAIT)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  kthread_disable(s.thread);

  // ...but the connect should still complete.
  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // Should be able to pass data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, 50));
  kthread_enable(s.thread);
  KEXPECT_EQ(0, finish_op(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void connect_gets_to_closed_test(void) {
  KTEST_BEGIN("TCP: connect() (socket gets to CLOSED)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  kthread_disable(s.thread);

  // ...but the connect should still complete.
  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // Should be able to pass data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, 50));
  kthread_enable(s.thread);
  KEXPECT_EQ(0, finish_op(&s));

  cleanup_tcp_test(&s);
}

static void shutdown_rd_during_connect(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // Should be able to send data still.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 104));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_rd_during_connect2(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) during connect(), then get data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Data should cause a RST.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));

  cleanup_tcp_test(&s);
}

static void shutdown_wr_during_connect(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_WR) during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // TODO(tcp): test sending packets and getting a RST

  cleanup_tcp_test(&s);
}

static void shutdown_rdwr_during_connect(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RDWR) during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // TODO(tcp): test sending packets and getting a RST

  cleanup_tcp_test(&s);
}

static void syn_bound_socket_test(void) {
  KTEST_BEGIN("TCP: get SYN on bound but unconnected socket");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  // SYNs and SYN_ACKs should get a RST.
  SEND_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 101));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 0));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_testA(void) {
  KTEST_BEGIN("TCP: simultaneous connect() #1");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // Read/write in SYN_RCVD shouldn't work.
  char c;
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, &c, 1));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, "123", 3));

  // RSTs outside the window should be ignored.
  SEND_PKT(&s, RST_PKT(/* seq */ 499, /* ack */ 101));
  SEND_PKT(&s, RST_PKT(/* seq */ 500, /* ack */ 101));
  SEND_PKT(&s, RST_PKT(/* seq */ 501 + 100000, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // RSTs in the window but not at the next sequence number should get a
  // challenge ACK.  They should not count as an ACK to complete connecting.
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, RST_PKT(/* seq */ 512, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // Data, FINs, and SYNs not aligned with the next sequence number should all
  // be ignored.
  SEND_PKT(&s, SYN_PKT(/* seq */ 502, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 499, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 100000, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 502, /* ack */ 101, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 499, /* ack */ 101, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s,
           SYNACK_PKT(/* seq */ 100000, /* ack */ 101, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  SEND_PKT(&s, DATA_PKT(/* seq */ 502, /* ack */ 101, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 490, /* ack */ 101, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 100000, /* ack */ 101, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  SEND_PKT(&s, FIN_PKT(/* seq */ 502, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 490, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 100000, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // ACK to complete the connection.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Pass some data in both directions.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 104, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 504));
  KEXPECT_STREQ("xyz", do_read(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 3));
  cleanup_tcp_test(&s);
}

static void simultaneous_connect_testB(void) {
  KTEST_BEGIN("TCP: simultaneous connect() #2");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // SYNs and SYN/ACKs aligned with the start of the window should get an ACK
  // but be ignored.
  SEND_PKT(&s, SYN_PKT(/* seq */ 501, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 501, /* ack */ 101, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 16384));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // ACKs that are not exactly aligned with our SYN should be ignored.
  // Note: the RFC says that we should send a RST for some of these.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 100));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 99));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 90 - 100000));
  KEXPECT_FALSE(raw_has_packets(&s));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 100000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // Data that is aligned, but with an unaligned ACK, should be ignored (and
  // challenge ACK sent if in the future).
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 100, "fff"));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 99, "fff"));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 90 - 100000, "fff"));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 100000, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // ...and same with aligned FINs.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 100));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 99));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 90 - 100000));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 100000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // ACK to complete the connection.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);
}

static void simultaneous_connect_rst_test(void) {
  KTEST_BEGIN("TCP: simultaneous connect() (gets RST)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(-ECONNREFUSED, finish_op(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_rst_test2(void) {
  KTEST_BEGIN("TCP: simultaneous connect() (gets RST with bad ACK)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 100));
  KEXPECT_EQ(-ECONNREFUSED, finish_op(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_rst_test3(void) {
  KTEST_BEGIN("TCP: simultaneous connect() (gets RST with bad ACK #2)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 100000));
  KEXPECT_EQ(-ECONNREFUSED, finish_op(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_rst_test4(void) {
  KTEST_BEGIN("TCP: simultaneous connect() (gets RST, with data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // Send RST.
  test_packet_spec_t pkt = DATA_PKT(/* seq */ 501, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  KEXPECT_EQ(-ECONNREFUSED, finish_op(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_data_test(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), ACK with data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // DATA+ACK to complete the connection.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Pass some data in both directions.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 104));

  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 104, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 507));
  KEXPECT_STREQ("123xyz", do_read(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 6));
  cleanup_tcp_test(&s);
}

static void simultaneous_connect_data_test2(void) {
  KTEST_BEGIN(
      "TCP: simultaneous connect(), ACK with data (overlaps start of window)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // DATA+ACK to complete the connection.
  SEND_PKT(&s, DATA_PKT(/* seq */ 500, /* ack */ 101, "x123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Pass some data in both directions.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 104));

  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 104, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 507));
  KEXPECT_STREQ("123xyz", do_read(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 6));
  cleanup_tcp_test(&s);
}

// This is technically an invalid packet, since it includes sequence numbers
// that should never be sent.  Our handling is possibly incorrect, but keep the
// test to make sure at least we don't crash on it.
static void simultaneous_connect_data_test3(void) {
  KTEST_BEGIN(
      "TCP: simultaneous connect(), ACK with data (overlaps start of window, "
      "before ISS)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // DATA+ACK to complete the connection.
  SEND_PKT(&s, DATA_PKT(/* seq */ 497, /* ack */ 101, "xyza123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Pass some data in both directions.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 104));

  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 104, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 507));
  KEXPECT_STREQ("123xyz", do_read(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 6));
  cleanup_tcp_test(&s);
}

static void simultaneous_connect_datafin_test(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), ACK with data + FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // DATA+ACK to complete the connection.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));
  KEXPECT_STREQ("123", do_read(s.socket));

  // Pass some data.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 505, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 104));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_fin_test(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), ACK with FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  // DATA+ACK to complete the connection.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  // Pass some data.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 502, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 104));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_rd_test(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_RD) in SYN_RCVD");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  // ACK to complete the connection.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Should still be able to send data.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 0));
  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_rd_test2(void) {
  KTEST_BEGIN(
      "TCP: simultaneous connect(), shutdown(SHUT_RD) in SYN_RCVD then data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  // Data that is unaligned or with mismatched ACK should still be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 502, /* ack */ 101, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 490, /* ack */ 101, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 100000, /* ack */ 101, "fff"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // ACK to complete the connection.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Should still be able to send data.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // If we receive data, reset the connection.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 104, "123"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 104, /* ack */ 501));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_rd_test3(void) {
  KTEST_BEGIN(
      "TCP: simultaneous connect(), shutdown(SHUT_RD) in SYN_RCVD then data on "
      "the first ACK");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  // ACK to complete the connection, but include data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  // Perhaps this should be ECONNRESET, but this matches the behavior
  // post-established if e.g. recv() is called.
  KEXPECT_EQ(0, finish_op(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "fgh", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  // ACK the SYN only.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Complete the close.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test2(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD #2");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // ACK the SYN only; include some data for good measure.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  KEXPECT_STREQ("abc", do_read(s.socket));

  // Complete the close.
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test3(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD #3");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // ACK the SYN and FIN; include some data for good measure.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));
  KEXPECT_STREQ("abc", do_read(s.socket));

  // Complete the close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test4(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD #4");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // ACK the SYN and FIN, no data.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Complete the close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test5(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD #5");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Complete the close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test6(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD #6");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Do a simultaneous close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_shutdown_wr_test7(void) {
  KTEST_BEGIN("TCP: simultaneous connect(), shutdown(SHUT_WR) in SYN_RCVD #7");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Do a simultaneous close, WITH data.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));
  KEXPECT_STREQ("abc", do_read(s.socket));
  char c;
  KEXPECT_EQ(0, vfs_read(s.socket, &c, 1));

  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

// TODO(tcp): test retransmission of SYNACK in SYN_RCVD (from LISTEN) state.
// TODO(tcp): allow send() in SYN_RCVD (and that FINs are queued after data).

static void connect_tests(void) {
  basic_connect_test();
  basic_connect_test2();
  connect_rst_test();
  multiple_connect_test();
  two_simultaneous_connects_test();
  rebind_tests();
  implicit_bind_test();
  get_addrs_during_connect_test();
  connect_interrupted_test();
  connect_timeout_test();
  connect_gets_to_close_wait_test();
  connect_gets_to_closed_test();

  shutdown_rd_during_connect();
  shutdown_rd_during_connect2();
  shutdown_wr_during_connect();
  shutdown_rdwr_during_connect();

  syn_bound_socket_test();

  simultaneous_connect_testA();
  simultaneous_connect_testB();
  simultaneous_connect_rst_test();
  simultaneous_connect_rst_test2();
  simultaneous_connect_rst_test3();
  simultaneous_connect_rst_test4();
  simultaneous_connect_data_test();
  simultaneous_connect_data_test2();
  simultaneous_connect_data_test3();
  simultaneous_connect_datafin_test();
  simultaneous_connect_fin_test();

  simultaneous_connect_shutdown_rd_test();
  simultaneous_connect_shutdown_rd_test2();
  simultaneous_connect_shutdown_rd_test3();
  simultaneous_connect_shutdown_wr_test();
  simultaneous_connect_shutdown_wr_test2();
  simultaneous_connect_shutdown_wr_test3();
  simultaneous_connect_shutdown_wr_test4();
  simultaneous_connect_shutdown_wr_test5();
  simultaneous_connect_shutdown_wr_test6();
  simultaneous_connect_shutdown_wr_test7();
}

static void rst_during_established_test(void) {
  KTEST_BEGIN("TCP: RST during established (no data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send RST.
  // TODO(tcp): test this also with data having passed.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // TODO(tcp): test getting ECONNRESET from write.
  struct sockaddr_storage unused;
  KEXPECT_EQ(-EINVAL, net_getsockname(s.socket, (struct sockaddr*)&unused));
  KEXPECT_EQ(-EINVAL, net_getpeername(s.socket, (struct sockaddr*)&unused));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, "127.0.0.1", 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, "127.0.0.5", 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.1", 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.5", 80));

  // TODO(tcp): if SO_ERROR is implemented, test here as well.

  cleanup_tcp_test(&s);
}

static void rst_during_established_test2(void) {
  KTEST_BEGIN("TCP: RST during established (with data, different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send RST without data.
  SEND_PKT(&s, RST_PKT(/* seq */ 504, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Shouldn't read any data.
  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  cleanup_tcp_test(&s);
}

static void rst_during_established_test3(void) {
  KTEST_BEGIN("TCP: RST during established (with data, same packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send RST _with data_.
  test_packet_spec_t rst_data_pkt =
      DATA_PKT(/* seq */ 504, /* ack */ 101, "de");
  rst_data_pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, rst_data_pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Shouldn't read any data.
  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  cleanup_tcp_test(&s);
}

static void rst_during_established_blocking_recv_test(void) {
  KTEST_BEGIN("TCP: RST during established with blocking recv() (no data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  struct sockaddr_storage unused;
  KEXPECT_EQ(-EINVAL, net_getsockname(s.socket, (struct sockaddr*)&unused));
  KEXPECT_EQ(-EINVAL, net_getpeername(s.socket, (struct sockaddr*)&unused));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, "127.0.0.1", 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, "127.0.0.5", 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.1", 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.5", 80));

  cleanup_tcp_test(&s);
}

static void rst_during_established_blocking_recv_test2(void) {
  KTEST_BEGIN("TCP: RST during established with blocking recv() (with data, "
              "different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 497));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 504, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  kthread_enable(s.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  cleanup_tcp_test(&s);
}

static void rst_during_established_blocking_recv_test3(void) {
  KTEST_BEGIN("TCP: RST during established with blocking recv() (with data, "
              "same packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.thread);

  // Send RST _with data_.
  test_packet_spec_t rst_data_pkt =
      DATA_PKT(/* seq */ 501, /* ack */ 101, "abc");
  rst_data_pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, rst_data_pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  kthread_enable(s.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  cleanup_tcp_test(&s);
}

// There's no need for the equivalent of rst_during_established_test() because
// that's the standard FIN close that most tests exercise already.
static void fin_during_established_test2(void) {
  KTEST_BEGIN("TCP: FIN during established (with data, different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should be able to read the data.
  char buf[10];
  KEXPECT_EQ(1, vfs_read(s.socket, buf, 1));
  buf[1] = '\0';
  KEXPECT_STREQ("a", buf);
  KEXPECT_EQ(2, vfs_read(s.socket, buf, 10));
  buf[2] = '\0';
  KEXPECT_STREQ("bc", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void fin_during_established_test3(void) {
  KTEST_BEGIN("TCP: FIN during established (with data, same packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN _with data_.
  test_packet_spec_t fin_data_pkt =
      DATA_PKT(/* seq */ 504, /* ack */ 101, "de");
  fin_data_pkt.flags |= TCP_FLAG_FIN;
  SEND_PKT(&s, fin_data_pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 507));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should be able to read the data.
  char buf[10];
  KEXPECT_EQ(1, vfs_read(s.socket, buf, 1));
  buf[1] = '\0';
  KEXPECT_STREQ("a", buf);
  KEXPECT_EQ(4, vfs_read(s.socket, buf, 10));
  buf[4] = '\0';
  KEXPECT_STREQ("bcde", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void fin_during_established_blocking_recv_test(void) {
  KTEST_BEGIN("TCP: FIN during established with blocking recv() (no data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Read should finish with EOF.
  KEXPECT_EQ(0, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void fin_during_established_blocking_recv_test2(void) {
  KTEST_BEGIN("TCP: FIN during established with blocking recv() (with data, "
              "different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Read should finish with the data.
  kthread_enable(s.thread);
  KEXPECT_EQ(3, finish_op(&s));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void fin_during_established_blocking_recv_test3(void) {
  KTEST_BEGIN("TCP: FIN during established with blocking recv() (with data, "
              "same packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN _with data_.
  test_packet_spec_t fin_data_pkt =
      DATA_PKT(/* seq */ 504, /* ack */ 101, "de");
  fin_data_pkt.flags |= TCP_FLAG_FIN;
  SEND_PKT(&s, fin_data_pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 507));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Read should finish with the data.
  kthread_enable(s.thread);
  KEXPECT_EQ(5, finish_op(&s));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

// Exact same as above, but no pending data in the buffer when the FIN comes in.
static void fin_during_established_blocking_recv_test3b(void) {
  KTEST_BEGIN("TCP: FIN during established with blocking recv() (with data, "
              "same packet, no pending data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.thread);

  // Send FIN _with data_.
  test_packet_spec_t fin_data_pkt =
      DATA_PKT(/* seq */ 501, /* ack */ 101, "de");
  fin_data_pkt.flags |= TCP_FLAG_FIN;
  SEND_PKT(&s, fin_data_pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Read should finish with the data.
  kthread_enable(s.thread);
  KEXPECT_EQ(2, finish_op(&s));
  buf[2] = '\0';
  KEXPECT_STREQ("de", buf);

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 504));
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void fin_and_rst_test(void) {
  KTEST_BEGIN("TCP: FIN and RST together");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.thread);

  // Send RST with data and FIN.
  test_packet_spec_t rst_data_pkt =
      DATA_PKT(/* seq */ 501, /* ack */ 101, "abc");
  rst_data_pkt.flags |= TCP_FLAG_RST | TCP_FLAG_FIN;
  SEND_PKT(&s, rst_data_pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  kthread_enable(s.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  // TODO(tcp): test write() as well.

  cleanup_tcp_test(&s);
}

// TODO(tcp): version of this test with SHUT_RD called when that is implemented.
static void read_after_shutdown_test(void) {
  KTEST_BEGIN("TCP: read buffered data after FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  // Should still be able to read the data.
  char buf[10];
  KEXPECT_EQ(1, vfs_read(s.socket, buf, 1));
  buf[1] = '\0';
  KEXPECT_STREQ("a", buf);
  KEXPECT_EQ(2, vfs_read(s.socket, buf, 10));
  buf[2] = '\0';
  KEXPECT_STREQ("bc", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

static void read_after_shutdown_test2(void) {
  KTEST_BEGIN("TCP: read buffered data after FIN (in LAST_ACK)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));

  // Should still be able to read the data in LAST_ACK.
  char buf[10];
  KEXPECT_EQ(1, vfs_read(s.socket, buf, 1));
  buf[1] = '\0';
  KEXPECT_STREQ("a", buf);
  KEXPECT_EQ(2, vfs_read(s.socket, buf, 10));
  buf[2] = '\0';
  KEXPECT_STREQ("bc", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  // Finish close.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void data_after_fin_test(void) {
  KTEST_BEGIN("TCP: data packet after FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // Send more data --- should be dropped, no ACKs.
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 101, "d"));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "e"));
  // Sorta an edge case, but we send an ACK for this "out of order" packet even
  // though we're past a received FIN.  This is, I think, RFC-compliant, if
  // sorta weird.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // Should be able to read the data.
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));

  // Send _more_ data.
  // TODO(tcp): enable this when out-of-order ACKs are handled properly.
#if 0
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 101, "d"));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "e"));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
#endif

  // Send data with the ACK for the fin.  The ACK should be read, but the data
  // should be dropped.
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 102, "d"));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 102, "e"));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

static void rst_after_fin_test(void) {
  KTEST_BEGIN("TCP: RST packet after FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // We should be in CLOSE_WAIT. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should get ECONNRESET.
  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

// TODO(tcp): this same test, but with a blocking write.
static void rst_after_fin_test2(void) {
  KTEST_BEGIN("TCP: RST packet after FIN (with blocking read)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  // We should be in CLOSE_WAIT. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should get ECONNRESET.
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

static void rst_after_fin_test3(void) {
  KTEST_BEGIN("TCP: RST packet after FIN (with blocking read, data available)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // We should be in CLOSE_WAIT. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should get ECONNRESET.
  kthread_enable(s.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

static void rst_in_lastack_test(void) {
  KTEST_BEGIN("TCP: RST packet in LAST_ACK");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));

  // We should be in LAST_ACK. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Connection should be closed, but we should still be able to get data.
  // The RFC is unclear on whether this should be the case, but I think we
  // should either be able to get the data OR this should return -ECONNRESET ---
  // we shouldn't just return EOF and silently drop the data.
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

// This is arguably redundant (we should have tests for RST in LAST_ACK, above,
// and also a pending read when FIN is received).
static void rst_in_lastack_test2(void) {
  KTEST_BEGIN("TCP: RST packet in LAST_ACK (with blocking read)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));

  // We should be in LAST_ACK. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // As above, should still be able to get the data.
  kthread_enable(s.thread);
  KEXPECT_EQ(3, finish_op(&s));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

static void basic_established_recv_test(void) {
  KTEST_BEGIN("TCP: basic data passing (receive)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, buf, 100));

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, buf, 100));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, buf, 100));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));

  // Poke and prod some other methods while read() is blocked.
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, "127.0.0.1", 1234));
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, "127.0.0.1", 1234));

  struct sockaddr_in bound_addr;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ("127.0.0.1", ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(s.tcp_addr.sin_port, bound_addr.sin_port);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 495));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 508, /* wndsize */ 493));
  KEXPECT_EQ(3, finish_op(&s));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  SEND_PKT(&s, DATA_PKT(/* seq */ 508, /* ack */ 101, "hi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 494));
  KEXPECT_EQ(6, vfs_read(s.socket, buf, 100));
  buf[6] = '\0';
  KEXPECT_STREQ("defghi", buf);

  KEXPECT_TRUE(start_read(&s, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 510, /* ack */ 101, "12345"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 515));
  KEXPECT_EQ(5, finish_op(&s));
  buf[5] = '\0';
  KEXPECT_STREQ("12345", buf);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 515, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 516));

  // Should now return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 516));
  SEND_PKT(&s, ACK_PKT(/* seq */ 516, /* ack */ 102));

  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  cleanup_tcp_test(&s);
}

static void interrupted_recv_test(void) {
  KTEST_BEGIN("TCP: interrupted recv()");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void interrupted_recv_test2(void) {
  KTEST_BEGIN("TCP: interrupted recv() (data pending as well)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.thread);

  proc_kill_thread(s.thread, SIGUSR1);
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // It would also be OK for this to read the data.
  kthread_enable(s.thread);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_test(void) {
  KTEST_BEGIN("TCP: recieve out of order data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  // It would be allowed for it to cache the OOO packet and make it all
  // available now, but we don't currently.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 497));
  KEXPECT_EQ(3, finish_op(&s));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));
  cleanup_tcp_test(&s);
}

static void recv_timeout_test(void) {
  KTEST_BEGIN("TCP: recv() timeout");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {9999, 9999};
  socklen_t slen = sizeof(struct apos_timeval);
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, &slen));
  KEXPECT_EQ(0, tv.tv_sec);
  KEXPECT_EQ(0, tv.tv_usec);

  // Try invalid values.
#if ARCH_IS_64_BIT
  tv.tv_sec = INT64_MAX;
  tv.tv_usec = 0;
  KEXPECT_EQ(-ERANGE, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                                     sizeof(tv)));
#endif
  tv.tv_sec = 0;
  tv.tv_usec = 1000001;
  KEXPECT_EQ(-ERANGE, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                                     sizeof(tv)));
  tv.tv_sec = 0;
  tv.tv_usec = -1;
  KEXPECT_EQ(-ERANGE, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                                     sizeof(tv)));
  tv.tv_sec = -1;
  tv.tv_usec = 0;
  KEXPECT_EQ(-ERANGE, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                                     sizeof(tv)));

  // Test actual timeout.
  tv.tv_sec = 0;
  tv.tv_usec = 50 * 1000;
  KEXPECT_EQ(0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                                     sizeof(tv)));

  char buf[10];
  apos_ms_t start = get_time_ms();
  KEXPECT_EQ(-ETIMEDOUT, vfs_read(s.socket, buf, 10));
  apos_ms_t end = get_time_ms();
  KEXPECT_GE(end - start, 50);
  KEXPECT_LE(end - start, 500);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void recv_timeout_test2(void) {
  KTEST_BEGIN("TCP: recv() timeout (set to zero)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 0};
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, 50));
  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void recv_timeout_test3(void) {
  KTEST_BEGIN("TCP: recv() timeout (data received)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 50 * 1000};
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 1));
  kthread_disable(s.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, 60));

  // Read the data in _this_ thread.
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));

  // Let the other thread wake up.  It should realize that it timed out.
  kthread_enable(s.thread);
  KEXPECT_EQ(-ETIMEDOUT, finish_op(&s));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void recv_timeout_test4(void) {
  KTEST_BEGIN("TCP: recv() timeout (timeout below ms granularity)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 10};
  KEXPECT_EQ(0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv,
                                     sizeof(tv)));

  socklen_t slen = sizeof(struct apos_timeval);
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, &slen));
  KEXPECT_EQ(sizeof(struct apos_timeval), slen);
  KEXPECT_EQ(0, tv.tv_sec);
  KEXPECT_EQ(1000, tv.tv_usec);

  char buf[10];
  apos_ms_t start = get_time_ms();
  KEXPECT_EQ(-ETIMEDOUT, vfs_read(s.socket, buf, 10));
  apos_ms_t end = get_time_ms();
  KEXPECT_LE(end - start, 50);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void established_tests(void) {
  basic_established_recv_test();
  rst_during_established_test();
  rst_during_established_test2();
  rst_during_established_test3();
  rst_during_established_blocking_recv_test();
  rst_during_established_blocking_recv_test2();
  rst_during_established_blocking_recv_test3();

  fin_during_established_test2();
  fin_during_established_test3();
  fin_during_established_blocking_recv_test();
  fin_during_established_blocking_recv_test2();
  fin_during_established_blocking_recv_test3();
  fin_during_established_blocking_recv_test3b();

  fin_and_rst_test();
  read_after_shutdown_test();
  read_after_shutdown_test2();
  data_after_fin_test();

  rst_after_fin_test();
  rst_after_fin_test2();
  rst_after_fin_test3();
  rst_in_lastack_test();
  rst_in_lastack_test2();

  interrupted_recv_test();
  interrupted_recv_test2();

  out_of_order_recv_test();

  recv_timeout_test();
  recv_timeout_test2();
  recv_timeout_test3();
  recv_timeout_test4();
}

static void recvbuf_size_test(void) {
  KTEST_BEGIN("TCP: SO_RCVBUF");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val;
  socklen_t vallen = sizeof(int);
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(16 * 1024, val);

  val = 1234;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, sizeof(int)));

  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  val = 100 * 1024 * 1024;
  KEXPECT_EQ(-EINVAL, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val,
                                     sizeof(int)));
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  // Send buffer should be untouched.
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(16 * 1024, val);

  // Now make sure we can't change it later.
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_EQ(-EISCONN, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val,
                                     sizeof(int)));
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 1234));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 1234));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  // Arguably should be EINVAL?  Doesn't really matter.
  KEXPECT_EQ(-EISCONN, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val,
                                      sizeof(int)));
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  cleanup_tcp_test(&s);
}

static void sendbuf_size_test(void) {
  KTEST_BEGIN("TCP: SO_SNDBUF");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val;
  socklen_t vallen = sizeof(int);
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(16 * 1024, val);

  val = 1234;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(int)));

  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  val = 100 * 1024 * 1024;
  KEXPECT_EQ(-EINVAL, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val,
                                     sizeof(int)));
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  // Recieve buffer should be untouched.
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(16 * 1024, val);

  // Now make sure we can't change it later.
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_EQ(-EISCONN, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val,
                                     sizeof(int)));
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  // Arguably should be EINVAL?  Doesn't really matter.
  KEXPECT_EQ(-EISCONN, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val,
                                      sizeof(int)));
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1234, val);

  cleanup_tcp_test(&s);
}

static void basic_send_test(void) {
  KTEST_BEGIN("TCP: basic data passing (send)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, "XXX", 3));

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, "XXX", 3));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, "XXX", 3));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 497));

  KEXPECT_EQ(2, vfs_write(s.socket, "de", 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "de"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ 495));

  // Receive a bit of data too.
  // TODO(tcp): test sending data with old ACK value and unsent (invalid) ACK.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 106, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 504));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("xyz", buf);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 106));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 505));

  // Should still be able to send data.
  KEXPECT_EQ(3, vfs_write(s.socket, "fgh", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 505, "fgh"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 109));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 109, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 110));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "fgh", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void basic_send_window_test(void) {
  KTEST_BEGIN("TCP: basic send window test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 1));

  KEXPECT_EQ(6, vfs_write(s.socket, "123456", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "1"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 10));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ 1));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 105, /* ack */ 501, "2"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  // Send FIN to start connection close.
  SEND_PKT(&s,
           FIN_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 502));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should not yet get a FIN.
  KEXPECT_FALSE(raw_has_packets_wait(&s, 10));

  // Trickle the data back slowly.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 106, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 502, "34"));

  // A future ACK and past ACK shouldn't cause FIN to be sent.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 109, /* wndsize */ 2));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 108, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 105, /* wndsize */ 2));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 103, /* wndsize */ 2));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 10));

  // Open the window just enough to get the data and the FIN in.
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 108, /* wndsize */ 3));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 108, /* ack */ 502, "56"));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 109));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 110));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 111));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

// As above, but ack buffered data just up to (but not including) the FIN.
static void basic_send_window_test2(void) {
  KTEST_BEGIN("TCP: basic send window test #2");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 2));

  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "12"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  // Send FIN to start connection close.
  SEND_PKT(&s,
           FIN_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 502));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  // Should not yet get a FIN.
  KEXPECT_FALSE(raw_has_packets_wait(&s, 10));

  // Trickle the data back slowly.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 106, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 502, "34"));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  // Open the window just enough to get the data but not the FIN in.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 108, /* wndsize */ 1));
  // TODO(tcp): fix this bug (should only send "5", not "5" + FIN)
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 108, /* ack */ 502, "5"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 110));
#if 0
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 108, /* ack */ 502, "5"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 109));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 109, /* wndsize */ 1));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 109, /* ack */ 502));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 109));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 110));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
#endif

  cleanup_tcp_test(&s);
}

static void basic_send_test_blocks(void) {
  KTEST_BEGIN("TCP: basic data passing (blocking send)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking. [abc] [] []
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 1));

  // Second send should send only 1 byte and buffer the rest. [abc] [d] [ef]
  KEXPECT_EQ(3, vfs_write(s.socket, "def", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "d"));
  // Don't ack it yet.

  // Next write should buffer some and not send any packets. [abc] [d] [efgh]
  KEXPECT_EQ(2, vfs_write(s.socket, "ghijk", 5));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 10));

  // The next write should block. [abc] [d] [efgh]
  KEXPECT_TRUE(start_write(&s, "ilmn"));

  // Finally send an ACK. [abcd] [] [efgh]
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ 3));

  // We should get three more bytes from the buffer.  [abcd] [efg] [h]
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 105, /* ack */ 501, "efg"));
  // ...don't ack yet.

  // The async write should finish having buffered one byte.
  KEXPECT_EQ(1, finish_op(&s));

  // Ack things and get the rest.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 108, /* wndsize */ 100));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 108, /* ack */ 501, "hi"));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // Send a FIN containing our final data ACK.
  KEXPECT_TRUE(do_standard_finish(&s, 9, 0));

  cleanup_tcp_test(&s);
}

// As above, but acks _all_ unacked data with a blocking thread.
static void basic_send_test_blocks2(void) {
  KTEST_BEGIN("TCP: basic data passing (blocking send 2)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));
  KEXPECT_TRUE(start_write(&s, "ghijkl"));

  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));

  // We should get the next write's data.  (note, 'f' never sent).
  KEXPECT_EQ(5, finish_op(&s));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "ghijk"));

  KEXPECT_TRUE(do_standard_finish(&s, 10, 0));

  cleanup_tcp_test(&s);
}

static void send_blocking_interrupted(void) {
  KTEST_BEGIN("TCP: blocking send interrupted");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  KEXPECT_TRUE(start_write(&s, "fgh"));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  // Finally send an ACK.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(do_standard_finish(&s, 5, 0));

  cleanup_tcp_test(&s);
}

static void send_timeout_test(void) {
  KTEST_BEGIN("TCP: send() timeout");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {9999, 9999};
  socklen_t slen = sizeof(struct apos_timeval);
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, &tv, &slen));
  KEXPECT_EQ(0, tv.tv_sec);
  KEXPECT_EQ(0, tv.tv_usec);

  // Try invalid values.
#if ARCH_IS_64_BIT
  tv.tv_sec = INT64_MAX;
  tv.tv_usec = 0;
  KEXPECT_EQ(-ERANGE, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, &tv,
                                     sizeof(tv)));
#endif
  tv.tv_sec = 0;
  tv.tv_usec = 1000001;
  KEXPECT_EQ(-ERANGE, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, &tv,
                                     sizeof(tv)));

  // Test actual timeout.
  tv.tv_sec = 0;
  tv.tv_usec = 50 * 1000;
  KEXPECT_EQ(0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, &tv,
                                     sizeof(tv)));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  apos_ms_t start = get_time_ms();
  KEXPECT_EQ(-ETIMEDOUT, vfs_write(s.socket, "hij", 3));
  apos_ms_t end = get_time_ms();
  KEXPECT_GE(end - start, 50);
  KEXPECT_LE(end - start, 500);
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(do_standard_finish(&s, 5, 0));

  cleanup_tcp_test(&s);
}

static void send_timeout_test2(void) {
  KTEST_BEGIN("TCP: send() timeout (timeout after wake)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 50 * 1000};
  KEXPECT_EQ(0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, &tv,
                                     sizeof(tv)));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));
  KEXPECT_TRUE(start_write(&s, "fgh"));
  kthread_disable(s.thread);
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 60));

  // Fill the buffer up again from another thread.
  KEXPECT_EQ(5, vfs_write(s.socket, "123456", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "12345"));

  kthread_enable(s.thread);
  KEXPECT_EQ(-ETIMEDOUT, finish_op(&s));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(do_standard_finish(&s, 10, 0));

  cleanup_tcp_test(&s);
}

static void send_error_test(void) {
  KTEST_BEGIN("TCP: send() has socket error");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNRESET, vfs_write(s.socket, "abc", 3));
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void send_error_test2(void) {
  KTEST_BEGIN("TCP: send() has socket error (RST acks sent data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 103));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNRESET, vfs_write(s.socket, "abc", 3));
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void send_error_test3(void) {
  KTEST_BEGIN("TCP: send() has socket error (RST acks all sent data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 105));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNRESET, vfs_write(s.socket, "abc", 3));
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void send_error_test4(void) {
  KTEST_BEGIN(
      "TCP: send() has socket error (RST acks data, buffered data ready)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(1, vfs_write(s.socket, "a", 1));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "a"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 102, /* wndsize */ 2));

  // Buffer more data; we should get some of it.
  KEXPECT_EQ(5, vfs_write(s.socket, "123456", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 102, /* ack */ 501, "12"));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 104));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNRESET, vfs_write(s.socket, "abc", 3));
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void send_blocking_error_test(void) {
  KTEST_BEGIN("TCP: send() timeout (timeout after wake)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));
  KEXPECT_TRUE(start_write(&s, "fgh"));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNRESET, finish_op(&s));
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void send_window_constricts_test(void) {
  KTEST_BEGIN("TCP: remote window constricts smaller than in-flight data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 5));
  KEXPECT_EQ(1, vfs_write(s.socket, "d", 1));
  KEXPECT_EQ(6, vfs_write(s.socket, "efghij", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "d"));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 105, /* ack */ 501, "efgh"));
  // Ack 'd' with a window size of 2, smaller than the outstanding data "efgh".
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ 2));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  KEXPECT_EQ(3, vfs_write(s.socket, "klm", 3));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // Ack 'efgh' with a closed window.
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 109, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // Open the window.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 109, /* wndsize */ 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 109, /* ack */ 501, "ijk"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 112, /* wndsize */ 100));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 112, /* ack */ 501, "lm"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 114, /* wndsize */ 100));

  KEXPECT_TRUE(do_standard_finish(&s, 13, 0));
  cleanup_tcp_test(&s);
}

static void send_ack_partial_packet(void) {
  KTEST_BEGIN("TCP: ACK for part of a packet");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));

  // Only ack 'ab'
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 103, /* wndsize */ 3));
  KEXPECT_EQ(5, vfs_write(s.socket, "defgh", 5));
  // Should only get 'de' ('c' is still unacked).
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "de"));

  // Now ack 'cde'.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "fgh"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 109, /* wndsize */ 3));

  KEXPECT_TRUE(do_standard_finish(&s, 8, 0));
  cleanup_tcp_test(&s);
}

static void send_during_close_wait(void) {
  KTEST_BEGIN("TCP: send() during CLOSE_WAIT");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  KEXPECT_EQ(3, vfs_write(s.socket, "def", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 502, "abc"));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 502, "def"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 107));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 107, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 108));

  cleanup_tcp_test(&s);
}

static void shutdown_with_data_buffered(void) {
  KTEST_BEGIN("TCP: shutdown() with buffered data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 2));
  KEXPECT_EQ(5, vfs_write(s.socket, "defgh", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "de"));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // We should _not_ yet get a FIN.
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // ACK; should get more data, still no FIN.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 106, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 502, "fg"));

  // ACK, then should get the last data plus a FIN.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 108, /* wndsize */ 1));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 108, /* ack */ 502, "h"));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 110));

  cleanup_tcp_test(&s);
}

static void shutdown_with_data_buffered_pending_send(void) {
  KTEST_BEGIN("TCP: shutdown() with buffered data (blocking send)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  s.wndsize = 3;

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  KEXPECT_EQ(2, vfs_write(s.socket, "12345", 5));

  // Start async write that should block.
  KEXPECT_TRUE(start_write(&s, "xyz"));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  ksigset_t new, old;
  ksigaddset(&new, SIGPIPE);
  // Prevent this thread from catching the signal.
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &new, &old));
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // The blocked write should fail.
  KEXPECT_EQ(-EPIPE, finish_op(&s));
  // Signal isn't pending because it was assigned to the now-dead write thread.

  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &old, NULL));

  // We should _not_ yet get a FIN.
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // ACK; should get FIN.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 104, /* wndsize */ 10));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 104, /* ack */ 502, "12"));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 107));

  cleanup_tcp_test(&s);
}

static void double_write_shutdown(void) {
  KTEST_BEGIN("TCP: double shutdown(SHUT_WR)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  SEND_PKT(&s, ACK_PKT(502, /* ack */ 102));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));

  cleanup_tcp_test(&s);
}

static void double_write_shutdown_with_data_buffered(void) {
  KTEST_BEGIN("TCP: double shutdown() with buffered data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ 2));
  KEXPECT_EQ(5, vfs_write(s.socket, "defgh", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "de"));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // We should _not_ yet get a FIN.
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // ACK; should get more data, still no FIN.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 106, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 502, "fg"));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // ACK, then should get the last data plus a FIN.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 108, /* wndsize */ 1));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 108, /* ack */ 502, "h"));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 110));

  cleanup_tcp_test(&s);
}

static void shutdown_with_zero_window(void) {
  KTEST_BEGIN("TCP: shutdown() sends FIN with zero window");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 502));

  // Ack the data packet and set window to zero (done after sending the FIN so
  // we can set the window size easily on the ACK).
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 502, /* ack */ 104, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN even though the window is zero.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_with_zero_recv_window(void) {
  KTEST_BEGIN("TCP: shutdown() rejects FIN with zero recv window");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Fill the window.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ WNDSIZE_ZERO));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 101));

  // Should get a duplicate ACK not covering the FIN.
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ WNDSIZE_ZERO));

  // Read the data (open the window) and try again.
  KEXPECT_STREQ("abcde", do_read(s.socket));

  // When the full packet is too long, we should drop the FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 506, /* ack */ 101, "12345"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("12345", do_read(s.socket));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 511, /* ack */ 101, "ABCD"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 516));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("ABCD", do_read(s.socket));

  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 516));
  SEND_PKT(&s, ACK_PKT(516, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void shutdown_read_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // We should still be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 104));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 502));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_read_blocking_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) with blocking read test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(0, finish_op(&s));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void shutdown_read_test_data_in_buffer(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) with data in buffer");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  // We should have discarded the data in the buffer.
  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // We should still be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 104));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 104));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 505));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_read_then_data_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) then gets data");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  // TODO(tcp): determine if this should send a RST and enable or delete.
#if 0
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
#endif

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void shutdown_read_then_datafin_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) then gets data + FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  // TODO(tcp): determine if this should send a RST and enable or delete.
#if 0
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
#endif

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void shutdown_read_then_data_with_buffered_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) then gets data (data buffered)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 504));
  // TODO(tcp): determine if this should send a RST and enable or delete.
#if 0
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
#endif

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void shutdown_read_after_fin_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) after FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // We should still be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 502, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 104));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_rdwr_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RDWR) basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void shutdown_rdwr_after_rd_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RDWR) after SHUT_RD basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // SHUT_WR should not have happened (we arbitrarily do read before write).
  // We should still be able to send without blocking.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 502, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 104));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_rdwr_after_wr_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RDWR) after SHUT_WR basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));

  // The RD shutdown should have happened.
  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void shutdown_rdwr_after_rdwr_test(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RDWR) after SHUT_RDWR basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));

  // The RD shutdown should have happened.
  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // The WR should have also happened.
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void shutdown_invalid_test(void) {
  KTEST_BEGIN("TCP: shutdown() invalid args");
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);

  KEXPECT_EQ(-EINVAL, net_shutdown(sock, 0));
  KEXPECT_EQ(-EINVAL, net_shutdown(sock, 4));
  KEXPECT_EQ(-EINVAL, net_shutdown(sock, 100));
  KEXPECT_EQ(0, vfs_close(sock));
}

// TODO(tcp): more send tests needed:
//  - receive after shutdown

static void send_tests(void) {
  basic_send_test();
  basic_send_window_test();
  basic_send_window_test2();
  basic_send_test_blocks();
  basic_send_test_blocks2();
  send_blocking_interrupted();
  send_timeout_test();
  send_timeout_test2();
  send_error_test();
  send_error_test2();
  send_error_test3();
  send_error_test4();
  send_blocking_error_test();
  send_window_constricts_test();
  send_ack_partial_packet();
  send_during_close_wait();
  shutdown_with_data_buffered();
  shutdown_with_data_buffered_pending_send();
  double_write_shutdown();
  double_write_shutdown_with_data_buffered();
  shutdown_with_zero_window();
  shutdown_with_zero_recv_window();

  shutdown_read_test();
  shutdown_read_blocking_test();
  shutdown_read_test_data_in_buffer();
  shutdown_read_then_data_test();
  shutdown_read_then_datafin_test();
  shutdown_read_then_data_with_buffered_test();
  shutdown_read_after_fin_test();

  shutdown_rdwr_test();
  shutdown_rdwr_after_rd_test();
  shutdown_rdwr_after_wr_test();
  shutdown_rdwr_after_rdwr_test();

  shutdown_invalid_test();
}

static void data_retransmit_test1(void) {
  KTEST_BEGIN("TCP: data packet retransmitted");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Test #1: retransmit exact same packet
  // First:  |abc|
  // Second: |abc|
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Retransmit, and get duplicate ack.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  KEXPECT_STREQ("abc", do_read(s.socket));


  // Test #2: retransmit overlapping start of window.
  // First:  |abc|
  // Second:   |Cdef|
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cdef"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 507));

  KEXPECT_STREQ("def", do_read(s.socket));


  // Send more data, then retransmit overlapping the start of the window (same
  // as above, just with buffered data).
  // First:  |hij|
  // Second:   |Jklm|
  SEND_PKT(&s, DATA_PKT(/* seq */ 507, /* ack */ 101, "hij"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 510));
  SEND_PKT(&s, DATA_PKT(/* seq */ 509, /* ack */ 101, "Jklm"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 513));

  KEXPECT_STREQ("hijklm", do_read(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 12));

  cleanup_tcp_test(&s);
}

static void data_past_window_test(void) {
  KTEST_BEGIN("TCP: data packet extends past window");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 2));

  // Send packet that extends past the end of the window and overlaps the
  // current start.  This must be dropped.
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cdef"));
  // Should get duplicate ACK.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 2));

  // Now try just enough to fill the window.
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  // This should be accepted.
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("abcde", do_read(s.socket));


  // Test #2: as above, but is exactly aligned with start of window (still too
  // long).  This should be trimmed.
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 2));
  SEND_PKT(&s, DATA_PKT(/* seq */ 509, /* ack */ 101, "4567"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("12345", do_read(s.socket));

  // Test #3: extends past window and doesn't align with start of window.
  // Should be dropped.
  SEND_PKT(&s, DATA_PKT(/* seq */ 512, /* ack */ 101, "567890abcdefg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
  // TODO(tcp): enable this once poll() is implemented
  // KEXPECT_FALSE(socket_has_data(s.socket, 0));

  // Test #4: doesn't align wih start of window, but is within window.  Should
  // be dropped.
  SEND_PKT(&s, DATA_PKT(/* seq */ 512, /* ack */ 101, "X"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
  // TODO(tcp): enable this once poll() is implemented
  // KEXPECT_FALSE(socket_has_data(s.socket, 0));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 10));

  cleanup_tcp_test(&s);
}

// Basically exactly the same as above, but with FINs past end-of-window.
static void data_fin_past_window_test(void) {
  KTEST_BEGIN("TCP: data packet extends past window (with FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 2));

  // Send packet that extends past the end of the window and overlaps the
  // current start.  This must be dropped.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 503, /* ack */ 101, "Cdef"));
  // Should get duplicate ACK.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 2));

  // Now try just enough to fill the window.
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  // This should be accepted.
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("abcde", do_read(s.socket));


  // Test #2: as above, but is exactly aligned with start of window (still too
  // long).  This should be trimmed (and FIN ignored).
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 2));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 509, /* ack */ 101, "4567"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("12345", do_read(s.socket));

  // Test #3: extends past window and doesn't align with start of window.
  // Should be dropped.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 512, /* ack */ 101, "567890abcdefg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
  // TODO(tcp): enable this once poll() is implemented
  // KEXPECT_FALSE(socket_has_data(s.socket, 0));

  // Test a correct in-window FIN with data that starts before the window.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 509, /* ack */ 101, "456789"));

  // Should get an ACK.
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 516, /* wndsize */ 1));
  KEXPECT_STREQ("6789", do_read(s.socket));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 516));
  SEND_PKT(&s, ACK_PKT(/* seq */ 516, /* ack */ 102));

  cleanup_tcp_test(&s);
}

// As above, but with a FIN that starts right at the start of the window.
static void data_fin_past_window_test2(void) {
  KTEST_BEGIN("TCP: data+FIN when FIN aligns with start of window");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 2));

  // Send a data+FIN where everything is before the window.  Should be dropped
  // with an ACK reply.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "AB"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 2));

  // Send a data+FIN where the data is all out-of-window, but the FIN is the
  // next sequence number expected.  This should be accepted.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 502, /* ack */ 101, "BC"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 505, /* wndsize */ 2));
  KEXPECT_STREQ("abc", do_read(s.socket));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void data_retransmit_blocked(void) {
  KTEST_BEGIN("TCP: data packet retransmitted doesn't wake blocked read");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_STREQ("abc", do_read(s.socket));

  // Start blocked read.
  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));

  // Retransmit, and get duplicate ack.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // The blocked read shouldn't have finished.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op_done, BLOCK_VERIFY_MS));

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cd"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_EQ(1, finish_op(&s));
  buf[1] = '\0';
  KEXPECT_STREQ("d", buf);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 4));

  cleanup_tcp_test(&s);
}

static void rst_out_of_order(void) {
  KTEST_BEGIN("TCP: RST received out of order");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 6));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 3));

  // Send a variety of out-of-window RSTs, all should be ignored.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));
  SEND_PKT(&s, RST_PKT(/* seq */ 503, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));
  SEND_PKT(&s, RST_PKT(/* seq */ 507, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));
  SEND_PKT(&s, RST_PKT(/* seq */ 516, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // Test with data, SYN, and FIN as well.
  test_packet_spec_t pkt = DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde");
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  pkt = SYN_PKT(/* seq */ 503, /* ack */ 101);
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  pkt = SYN_PKT(/* seq */ 507, /* ack */ 101);
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  pkt = FIN_PKT(/* seq */ 503, /* ack */ 101);
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  pkt = FIN_PKT(/* seq */ 507, /* ack */ 101);
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // RSTs sent in window (but not aligned with the start) should result in a
  // challenge ACK, but otherwise no processing.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 3));
  SEND_PKT(&s, RST_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 3));

  // ...and again test with data/SYN/FIN.
  pkt = DATA_PKT(/* seq */ 505, /* ack */ 101, "e");
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 3));

  pkt = SYN_PKT(/* seq */ 505, /* ack */ 101);
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 3));

  pkt = FIN_PKT(/* seq */ 505, /* ack */ 101);
  pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 3));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void repeat_ack_test(void) {
  KTEST_BEGIN("TCP: duplicate ACK test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send some repeat acks of the SYN.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send and ACK some data.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // Send various other "old" ACKs.  None should update the window, all should
  // be ignored.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 1));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 99, /* wndsize */ 1));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 103, /* wndsize */ 1));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 100, /* wndsize */ 1));
  KEXPECT_FALSE(raw_has_packets(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "def", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "def"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 107));

  // Send "future" ACKs.  Each of these should trigger a reply ACK, but should
  // not update the window (or otherwise be processed).
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 108, /* wndsize */ 1));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 112, /* wndsize */ 1));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 501));
  test_packet_spec_t pkt = DATA_PKT(/* seq */ 501, /* ack */ 112, "XYZ");
  pkt.wndsize = 1;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 501));
  pkt = DATA_FIN_PKT(/* seq */ 501, /* ack */ 112, "xyz");
  pkt.wndsize = 1;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 501));

  // Check the window again.
  KEXPECT_EQ(3, vfs_write(s.socket, "ghi", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 107, /* ack */ 501, "ghi"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 110));

  // Repeat ACKs with the same seq/ack _should_ update the window.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 110, /* wndsize */ 2));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 110, /* wndsize */ 1));
  KEXPECT_EQ(3, vfs_write(s.socket, "jkl", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 110, /* ack */ 501, "j"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 111, /* ack */ 501, "kl"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 113));
  KEXPECT_TRUE(do_standard_finish(&s, 12, 0));

  cleanup_tcp_test(&s);
}

static void repeat_syn_test(void) {
  KTEST_BEGIN("TCP: retransmitted SYN test");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send some repeats of the SYN/ACK, and SYNs before the window.  They should
  // trigger an ACK.  Try with data as well.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 499, /* ack */ 101, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  test_packet_spec_t pkt = DATA_PKT(/* seq */ 500, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  pkt = DATA_PKT(/* seq */ 499, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // Likewise, SYNs after the window should be ignored and trigger an ACK.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 510, /* ack */ 101, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 520, /* ack */ 101, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  pkt = DATA_PKT(/* seq */ 510, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 520, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // SYNs inside the window, or with data that overlaps the window, should be
  // treated the same. In theory we could handle SYNs before the window with
  // data (or FINs) inside the window, but currently just drop them.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 501, /* ack */ 101, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 502, /* ack */ 101, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  pkt = DATA_PKT(/* seq */ 500, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  pkt = DATA_PKT(/* seq */ 501, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  pkt = DATA_PKT(/* seq */ 501, /* ack */ 101, "abcdefg");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  pkt = DATA_PKT(/* seq */ 505, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  pkt = DATA_FIN_PKT(/* seq */ 500, /* ack */ 101, "abc");
  pkt.flags |= TCP_FLAG_SYN;
  SEND_PKT(&s, pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  // Verify after all that we can still send and receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "123"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 104));

  // Test sending SYNs in other states.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 104));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, SYNACK_PKT(/* seq */ 505, /* ack */ 104, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 505));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 505));

  SEND_PKT(&s, SYNACK_PKT(/* seq */ 505, /* ack */ 104, /* wndsize */ 500));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 105, /* ack */ 505));

  SEND_PKT(&s, ACK_PKT(505, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void ooo_tests(void) {
  data_retransmit_test1();
  data_past_window_test();
  data_fin_past_window_test();
  data_fin_past_window_test2();
  data_retransmit_blocked();
  rst_out_of_order();
  repeat_ack_test();
  repeat_syn_test();
}

static void active_close1(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  // Now we're in FIN_WAIT_1.

  // Send duplicate ACK.  Should still be in FIN_WAIT_1.
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 101));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // We should still be able to receive data (do NOT ACK the FIN).
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("abc", do_read(s.socket));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A SYN in FIN_WAIT_1 should get a challenge ACK and be ignored.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 501, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 504, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 504, /* ack */ 102, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Should not be able to write in FIN_WAIT_1.
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "fgh", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(504, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // We should still be able to receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 102, "def"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  KEXPECT_STREQ("def", do_read(s.socket));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // A SYN in FIN_WAIT_2 should get a challenge ACK and be ignored.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 504, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 507, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 507, /* ack */ 102, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Should not be able to write in FIN_WAIT_2.
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "fgh", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 507, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));
  KEXPECT_FALSE(raw_has_packets(&s));

  // In TIME_WAIT, a SYN should get a challenge ACK.
  SEND_PKT(&s, SYN_PKT(/* seq */ 508, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));
  SEND_PKT(&s, SYN_PKT(/* seq */ 507, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));
  SEND_PKT(&s, SYN_PKT(/* seq */ 707, /* ack */ 502));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));
  SEND_PKT(&s, SYN_PKT(/* seq */ 107, /* ack */ 2));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));

  // Data should be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 507, /* ack */ 102, "abc"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should not be able to write in TIME_WAIT.
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "fgh", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Don't test retransmitted FIN (tested below).

  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  int sock2 = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock2, 0);
  KEXPECT_EQ(0, do_bind(sock2, "127.0.0.1", 0x1234));
  KEXPECT_EQ(-EADDRINUSE, do_connect(sock2, "127.0.0.1", 0x5678));
  KEXPECT_EQ(0, vfs_close(sock2));

  SEND_PKT(&s, RST_PKT(/* seq */ 508, /* ack */ 102));
  cleanup_tcp_test(&s);
}

// As above, but test the timing of the timeout (and skip the
// expensive/higher-variance functional tests during TIME_WAIT).
static void active_close1a(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT) timeout");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  // Now we're in FIN_WAIT_1.

  // Send duplicate ACK.  Should still be in FIN_WAIT_1.
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 101));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // We should still be able to receive data (do NOT ACK the FIN).
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("abc", do_read(s.socket));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(504, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // We should still be able to receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 102, "def"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  KEXPECT_STREQ("def", do_read(s.socket));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 507, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait for the timer to run out.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close1b(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT); "
      "retransmitted FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));

  // We should still be able to receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));

  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait _some_ time, but not the full MSL.
  ksleep(10);

  // Retransmitted FIN should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));

  // Wait for long enough that the original timer would expire, but the reset
  // timer (from the retransmitted FIN) should not.
  ksleep(20);

  // Retransmitted FIN should still get an ACK.
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));

  // Wait for the timer to run out.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

// Exact same as above, but with the retransmitted FIN coming with data (also
// retransmitted).
static void active_close1c(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT); "
      "retransmitted FIN (with data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 60));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));

  // We should still be able to receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));

  KEXPECT_STREQ("abc", do_read(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait _some_ time, but not the full MSL.
  ksleep(30);

  // Retransmitted FIN with data should get an ACK.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 502, /* ack */ 102, "bc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));

  // Wait for long enough that the original timer would expire, but the reset
  // timer (from the retransmitted FIN) should not.
  ksleep(30);

  // Retransmitted FIN should still get an ACK.
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));

  // Wait for the timer to run out.
  ksleep(60);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close1d(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT); "
      "TIME_WAIT gets FIN with misaligned sequence number");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 50));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));

  // We should still be able to receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));

  char buf[10];
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait _some_ time, but not the full MSL.
  ksleep(10);

  // Retransmitted FIN with mismatched seqno should get an ACK but NOT reset the
  // timer.
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  SEND_PKT(&s, FIN_PKT(/* seq */ 503, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));

  // These cases are ignored (they overlap the receive window, and hit a
  // different path that doesn't send a challenge ACK) --- it would be OK if
  // they did, though.
  SEND_PKT(&s, FIN_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_FALSE(raw_has_packets(&s));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 504, /* ack */ 102, "x"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait for long enough that the original timer expires.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close2(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT, with "
      "data+ACK)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, DATA_PKT(501, /* ack */ 102, "abc"));
  // Now we're in FIN_WAIT_2
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  KEXPECT_STREQ("abc", do_read(s.socket));

  SEND_PKT(&s, DATA_PKT(504, /* ack */ 102, "de"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 506));
  KEXPECT_STREQ("de", do_read(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  KEXPECT_FALSE(raw_has_packets(&s));

  // This time, try sending a RST to get us to CLOSED immediately.
  SEND_PKT(&s, RST_PKT(/* seq */ 507, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // TODO(tcp): use SO_ERROR to verify no error after RST here.

  cleanup_tcp_test(&s);
}

static void active_close3(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT, with "
      "data+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Send data+FIN to start connection close.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 102, "abc"));

  KEXPECT_STREQ("abc", do_read(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void active_close4(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 checks ACK)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send duplicate ACK.  Should still be in FIN_WAIT_1.
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 101));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  ksleep(20);  // Should still be in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // We should still be able to receive data (do NOT ACK the FIN).
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("abc", do_read(s.socket));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(504, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // We should still be able to receive data.
  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 102, "def"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 507));
  KEXPECT_STREQ("def", do_read(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 507, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 508));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, RST_PKT(/* seq */ 508, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  cleanup_tcp_test(&s);
}

static void active_close5(void) {
  KTEST_BEGIN("TCP: active close (buffered send bytes)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(
      &s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ WNDSIZE_ZERO));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send data, should not be sent due to zero window.
  KEXPECT_EQ(6, vfs_write(s.socket, "abcdef", 6));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Open the window a little bit.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2));

  // Should get data.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "ab"));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 103, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 103, /* ack */ 501, "cd"));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 105, /* ack */ 501, "ef"));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  // Now we're in FIN_WAIT_1.

  // Send duplicate ACK.  Should still be in FIN_WAIT_1.
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 105));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send partial ACK.  Should still be in FIN_WAIT_1.
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 106));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Ack the rest of the data _and_ the FIN together.
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 108));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 108));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 108, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 108));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  cleanup_tcp_test(&s);
}

static void active_close_fw1_rst(void) {
  KTEST_BEGIN("TCP: active close (RST in FIN_WAIT_1)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send some data then a RST.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("a", do_read_len(s.socket, 1));

  SEND_PKT(&s, RST_PKT(/* seq */ 504, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  cleanup_tcp_test(&s);
}

static void active_close_fw1_shutrd(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_1, no data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  // Now we're in FIN_WAIT_2
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  cleanup_tcp_test(&s);
}

static void active_close_fw1_shutrd_data(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_1, with data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 20));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));

  // Connection should now be reset.
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_shutrd_data2(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_1, with data "
              "but doesn't ACK the FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 20));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Connection should now be reset.
  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_shutrd_datafin(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_1, with DATA_FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 20));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  // Now we're in FIN_WAIT_1.

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));

  // Connection should now be reset.
  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw2_rst(void) {
  KTEST_BEGIN("TCP: active close (RST in FIN_WAIT_2)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send some data then a RST.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 504));
  KEXPECT_STREQ("a", do_read_len(s.socket, 1));

  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  SEND_PKT(&s, RST_PKT(/* seq */ 504, /* ack */ 102));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  cleanup_tcp_test(&s);
}

static void active_close_fw2_shutrd(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_2, no data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  cleanup_tcp_test(&s);
}

static void active_close_fw2_shutrd_data(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_2, with data)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 20));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));

  // Connection should now be reset.
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw2_shutrd_data2(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_2, with data "
              "but doesn't ACK the FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 20));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Connection should now be reset.
  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw2_shutrd_datafin(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_2, with DATA_FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 20));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(501, /* ack */ 102));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));

  // Connection should now be reset.
  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_to_tw(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> TIME_WAIT)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  // Now we're in FIN_WAIT_1.

  // Send FIN+ACK to start connection close and go straight to TIME_WAIT.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait for the timer to run out.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_to_tw_datafin(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> TIME_WAIT with data+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  // Now we're in FIN_WAIT_1.

  // Send FIN+ACK to start connection close and go straight to TIME_WAIT.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  KEXPECT_STREQ("abc", do_read(s.socket));

  // Wait for the timer to run out.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing1(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // In CLOSING, a SYN should get a challenge ACK.  The ACK should _not_ be
  // processed.
  SEND_PKT(&s, SYN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, SYN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, SYN_PKT(/* seq */ 502, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, SYN_PKT(/* seq */ 502, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, SYN_PKT(/* seq */ 707, /* ack */ 502));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, SYN_PKT(/* seq */ 107, /* ack */ 2));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Data should be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // As should a retransmitted FIN (get an ACK, at least).
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should not be able to write in CLOSING.
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "fgh", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // ACK the FIN to enter TIME_WAIT.
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Wait for the timer to run out.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing1b(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT), "
              "ACK in the " "past");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 105, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN (with ACK 'in the past').
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 105, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // ACK the FIN to enter TIME_WAIT.
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 105));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 105));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing1c(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT, "
              "DATA packet ACKs FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Data should be ignored, BUT the ack should be processed (weirdly) --- at
  // least that's my reading of the RFC.
  SEND_PKT(&s, DATA_PKT(/* seq */ 502, /* ack */ 102, "abc"));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing2(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT, with data+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // More data should be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 101, "def"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should be able to read in CLOSING.
  KEXPECT_STREQ("a", do_read_len(s.socket, 1));

  // ACK the FIN to enter TIME_WAIT.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  KEXPECT_STREQ("b", do_read_len(s.socket, 1));

  // Wait for the timer to run out.
  ksleep(40);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  KEXPECT_STREQ("c", do_read(s.socket));

  // Now a FIN should get a RST.
  SEND_PKT(&s, FIN_PKT(/* seq */ 50, /* ack */ 20));
  // TODO(tcp): fix this test
  //EXPECT_PKT(&s, RST_PKT(/* seq */ 20, /* ack */ 51));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing_rst(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> CLOSING -> RST)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // More data should be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 101, "def"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Should still be able to read the data.
  KEXPECT_STREQ("abc", do_read(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing_shutdown(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> CLOSING -> RST)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Should still be able to read the data.
  // Note: this is possibly weird --- are there other scenarios where you're
  // able to read data after calling shutdown(SHUT_RD)?
  KEXPECT_STREQ("abc", do_read(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing3(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT, with "
      "data+FIN+ACK)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // ACK the FIN to enter TIME_WAIT.  Data should be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 102, "123"));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  // Should still be able to read the data.
  KEXPECT_STREQ("abc", do_read(s.socket));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing4(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT, "
              "with data+FIN, read in CLOSING)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // A simultaneous FIN with an ACK "in the future" should be ignored.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 111));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 501));  // Challenge ack.
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  // Send simultaneous FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_STREQ("CLOSING", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // More data should be ignored.
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 101, "def"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should be able to read and get EOF in CLOSING.
  char buf[10];
  KEXPECT_STREQ("abc", do_read(s.socket));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  // ACK the FIN to enter TIME_WAIT.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 102));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

// Test what happens if we start an active close (by calling shutdown()), but
// the FIN is buffered, and then the _other_ side sends a FIN before ours
// actually is transmitted, turning it into a passive close.
static void active_close_buffered_to_passive(void) {
  KTEST_BEGIN("TCP: active close (FIN buffered, other side closes first)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(
      &s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ WNDSIZE_ZERO));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send data, should not be sent due to zero window.
  KEXPECT_EQ(6, vfs_write(s.socket, "abcdef", 6));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Open the window a little bit.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2));

  // Should get data.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "ab"));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Send a FIN, triggering a passive close.
  SEND_PKT(&s, FIN_PKT2(/* seq */ 501, /* ack */ 103, /* wndsize */ 1));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 103, /* ack */ 502, "c"));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 104, /* wndsize */ 1));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 502, "d"));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 105, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 105, /* ack */ 502, "ef"));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 108));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  cleanup_tcp_test(&s);
}

// As above, but with a FIN packet doesn't ACK the most recent data.
static void active_close_buffered_to_passive2(void) {
  KTEST_BEGIN("TCP: active close (FIN buffered, other side closes first)");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(
      &s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ WNDSIZE_ZERO));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send data, should not be sent due to zero window.
  KEXPECT_EQ(6, vfs_write(s.socket, "abcdef", 6));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Open the window a little bit.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2));

  // Should get data.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "ab"));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Send a FIN, triggering a passive close.  ACK doesn't hit most recent data,
  // so the wndsize update should be ignored.
  SEND_PKT(&s, FIN_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 103, /* ack */ 502));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 103, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 103, /* ack */ 502, "cd"));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 105, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 105, /* ack */ 502, "ef"));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));

  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 108));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  cleanup_tcp_test(&s);
}

static void active_close_tests(void) {
  active_close1();
  active_close1a();
  active_close1b();
  active_close1c();
  active_close1d();
  active_close2();
  active_close3();
  active_close4();
  active_close5();
  active_close_fw1_rst();
  active_close_fw1_shutrd();
  active_close_fw1_shutrd_data();
  active_close_fw1_shutrd_data2();
  active_close_fw1_shutrd_datafin();
  active_close_fw2_rst();
  active_close_fw2_shutrd();
  active_close_fw2_shutrd_data();
  active_close_fw2_shutrd_data2();
  active_close_fw2_shutrd_datafin();
  active_close_fw1_to_tw();
  active_close_fw1_to_tw_datafin();

  active_close_fw_to_closing1();
  active_close_fw_to_closing1b();
  active_close_fw_to_closing1c();
  active_close_fw_to_closing2();
  active_close_fw_to_closing_rst();
  active_close_fw_to_closing_shutdown();
  active_close_fw_to_closing3();
  active_close_fw_to_closing4();
  active_close_buffered_to_passive();
  active_close_buffered_to_passive2();
}

static void close_shutdown_test1(void) {
  KTEST_BEGIN("TCP: close() a disconnected socket");
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, vfs_close(sock));
}

static void close_shutdown_test2(void) {
  KTEST_BEGIN("TCP: close() bound socket");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));
  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  s.socket = -1;
  cleanup_tcp_test(&s);
}

static void close_shutdown_test3(void) {
  KTEST_BEGIN("TCP: close() connecting socket");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // TODO(aoates): figure out how to signal that the FD is closed to the other
  // thread, and have connect() return ECONNABORTED.
  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  s.socket = -1;
  cleanup_tcp_test(&s);
}

// As above, but kill the connect() call before calling close().
static void close_shutdown_test3b(void) {
  KTEST_BEGIN("TCP: close() connecting socket #2");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  s.socket = -1;
  cleanup_tcp_test(&s);
}

static void close_shutdown_test4(void) {
  KTEST_BEGIN("TCP: close() connected socket");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  int fd2 = vfs_dup(s.socket);

  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  // Shouldn't cause anything yet due to dup'd FD.
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(0, vfs_close(fd2));

  // Should cause the equivalent of shutdown(SHUT_RDWR).  The protocol handling
  // should continue even though the fd is gone.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void close_shutdown_test5(void) {
  KTEST_BEGIN("TCP: close() SYN-SENT socket");
  tcp_test_state_t s;
  init_tcp_test(&s, "127.0.0.1", 0x1234, "127.0.0.1", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "127.0.0.1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "127.0.0.1", 0x5678));

  // Do simultaneous connect.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // Force the connect() to finish.
  proc_kill_thread(s.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));
  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  // Should cause the equivalent of shutdown(SHUT_RDWR).  The protocol handling
  // should continue even though the fd is gone.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void close_shutdown_test(void) {
  close_shutdown_test1();
  close_shutdown_test2();
  close_shutdown_test3();
  close_shutdown_test3b();
  close_shutdown_test4();
  close_shutdown_test5();
}

void tcp_test(void) {
  KTEST_SUITE_BEGIN("TCP");
  const int initial_cache_size = vfs_cache_size();

  for (int i = 0; i < TEST_SEQ_ITERS; ++i) {
    g_seq_start = TEST_SEQ_START;
    if (TEST_SEQ_ITERS > 1) {
      // We only add the offset if doing more than one iteration.
      g_seq_start += (uint32_t)(i - TEST_SEQ_ITERS / 2);
    }
    klogf("g_seq_start = 0x%x\n", g_seq_start);
    tcp_key_test();
    seqno_test();
    tcp_socket_test();
    sockopt_test();
    bind_test();
    multi_bind_test();
    connect_tests();
    established_tests();
    recvbuf_size_test();
    sendbuf_size_test();
    send_tests();
    ooo_tests();
    active_close_tests();
    close_shutdown_test();
  }

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
