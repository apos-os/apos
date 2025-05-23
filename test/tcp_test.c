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
#include "common/errno.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/math.h"
#include "dev/char_dev.h"
#include "dev/dev.h"
#include "dev/net/tuntap.h"
#include "dev/timer.h"
#include "net/addr.h"
#include "net/bind.h"
#include "net/eth/eth.h"
#include "net/inet.h"
#include "net/ip/checksum.h"
#include "net/ip/ip4_hdr.h"
#include "net/ip/ip6_hdr.h"
#include "net/pbuf.h"
#include "net/socket/socket.h"
#include "net/socket/tcp/congestion.h"
#include "net/socket/tcp/coverage.h"
#include "net/socket/tcp/internal.h"
#include "net/socket/tcp/protocol.h"
#include "net/socket/tcp/tcp.h"
#include "net/socket/tcp/sockmap.h"
#include "net/util.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/hamlet.h"
#include "test/ktest.h"
#include "test/test_nic.h"
#include "test/test_params.h"
#include "test/test_point.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/net/socket/socket.h"
#include "user/include/apos/net/socket/tcp.h"
#include "user/include/apos/posix_signal.h"
#include "user/include/apos/time_types.h"
#include "user/include/apos/vfs/poll.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"
#include "vfs/vfs_internal.h"
#include "vfs/vfs_test_util.h"

#define TEST_SEQ_START (UINT32_MAX - 102)

// How many different start sequence numbers to run the tests with.  Normally
// will be 1, but crank up to ~20-30 (along with tweaking TEST_SEQ_START) to
// get good coverage of sequence number overflow scenarios.
#define TEST_SEQ_ITERS 1

// How long (in ms) to wait for async operations to confirm they're blocking.
// Increase this to make tests more stringent at the cost of running longer.
#define BLOCK_VERIFY_MS 10

// Multithreaded test parameters.
#define MT_TEST_READERS (3 * CONCURRENCY_TEST_THREADS_MULT)
#define MT_TEST_WRITERS (3 * CONCURRENCY_TEST_THREADS_MULT)
#define MT_CONNECT_ROUNDS (1 * CONCURRENCY_TEST_ITERS_MULT)
#define MT_WRITE_ROUNDS 2
#define MT_PORT 55827

#define TAP_SRC_IP "127.0.2.1"
#define TAP_DST_IP "127.0.2.2"

// IPs used for the TUN tests.
#define SRC_IP "127.0.1.1"
#define SRC_IP_2 "127.0.1.10"
#define DST_IP "127.0.1.2"
#define DST_IP_2 "127.0.1.3"
#define DST_IP_PREFIX "127.0.1"

// IPs used for tests that use an implicit bind rather than explicit (and
// therefore must be actually present on one of the interfaces).
#define IMPLICIT_SRC_IP SRC_IP
#define IMPLICIT_DST_IP DST_IP

// Constants for the real-socket tests.
#define SERVER_PORT 5000
#define LO_SRC_IP "127.0.0.2"
#define LO_DST_IP "127.0.0.3"
#define LO_DST_IP_PORT LO_DST_IP ":5000"

#define DEFAULT_MSS 536

#define RAW_RECV_BUF_SIZE 100

// A packet that's queued for a test to handle.  We have to track these packets
// explicitly because some tests have multiple destination IPs and we need to
// keep the packet streams separated.
typedef struct {
  struct sockaddr_storage_ip dst_ip;
  char packet[RAW_RECV_BUF_SIZE];
  ssize_t packet_len;
  list_link_t link;
} queued_packet_t;

// Global test state.  Ideally would be plumbed through the code rather than
// being global, but meh.  Should not be accessed by individual test cases, only
// test helpers.
typedef struct {
  // Sequence number to start with for the tests.
  uint32_t seq_start;

  // File descriptor for the TUN device for the test to read packets from.
  int tun_fd;

  // Chardev of the TUN, so we can write directly (skipping the VFS layer).
  char_dev_t* tun_chardev;

  // All queued packets, ready for a test to take.
  list_t packets;
} global_tcp_test_state_t;

static global_tcp_test_state_t g_tcp_test = {
  .seq_start = TEST_SEQ_START,
  .tun_fd = -1,
  .tun_chardev = NULL,
  .packets = LIST_INIT_STATIC,
};

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

static const char* sas2str(const struct sockaddr_storage* sas) {
  static char buf[SOCKADDR_PRETTY_LEN];
  return sockaddr2str((const struct sockaddr*)sas,
                      sizeof(struct sockaddr_storage), buf);
}

static void make_saddr(struct sockaddr_storage_ip* sas, const char* addr,
                       int port) {
  if (kstrchr(addr, ':') == 0) {
    struct sockaddr_in* saddr = (struct sockaddr_in*)sas;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = str2inet(addr);
    saddr->sin_port = htob16(port);
  } else {
    KEXPECT_EQ(0, str2sin6(addr, port, (struct sockaddr_in6*)sas));
  }
}

static bool has_sigpipe(void) {
  const ksigset_t sigset = proc_pending_signals(proc_current());
  return ksigismember(&sigset, SIGPIPE);
}

static int do_bind(int sock, const char* addr, int port) {
  struct sockaddr_storage_ip saddr;
  make_saddr(&saddr, addr, port);
  return net_bind(sock, (struct sockaddr*)&saddr, sizeof(saddr));
}

static int do_connect(int sock, const char* addr, int port) {
  struct sockaddr_storage_ip saddr;
  make_saddr(&saddr, addr, port);
  return net_connect(sock, (struct sockaddr*)&saddr, sizeof(saddr));
}

static int do_accept(int sock, char* addr_out) {
  struct sockaddr_storage_ip saddr;
  socklen_t slen = sizeof(saddr);
  *addr_out = '\0';
  int result = net_accept(sock, (struct sockaddr*)&saddr, &slen);
  if (result < 0) {
    return result;
  }

  sockaddr2str((const struct sockaddr*)&saddr, sizeof(saddr), addr_out);
  return result;
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
  if (!KEXPECT_TRUE(socket_has_data(sock, 0))) {
    return "<no data>";
  }
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

static int set_rto(int socket, int rto_ms) {
  int result =
      net_setsockopt(socket, IPPROTO_TCP, SO_TCP_RTO, &rto_ms, sizeof(rto_ms));
  if (result) {
    return result;
  }
  return net_setsockopt(socket, IPPROTO_TCP, SO_TCP_RTO_MIN, &rto_ms,
                        sizeof(rto_ms));
}

static int get_rto(int socket) {
  int rto_ms = 0;
  socklen_t len = sizeof(rto_ms);
  int result = net_getsockopt(socket, IPPROTO_TCP, SO_TCP_RTO, &rto_ms, &len);
  KEXPECT_EQ(0, result);
  return rto_ms;
}

static int get_cwnd(int socket) {
  int cwnd = 0;
  socklen_t len = sizeof(cwnd);
  int result = net_getsockopt(socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, &len);
  KEXPECT_EQ(0, result);
  return cwnd;
}

static int get_so_error(int socket) {
  int error = 0;
  socklen_t len = sizeof(error);
  int result = net_getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &len);
  KEXPECT_EQ(0, result);
  return error;
}

static int getsockname_inet(int socket, struct sockaddr_in* sin) {
  kmemset(sin, 0xab, sizeof(struct sockaddr_in));
  struct sockaddr_storage sas;
  int result = net_getsockname(socket, &sas);
  if (result < 0) return result;
  if (sas.sa_family == AF_INET) {
    kmemcpy(sin, &sas, sizeof(struct sockaddr_in));
  }
  return 0;
}

static int getpeername_inet(int socket, struct sockaddr_in* sin) {
  kmemset(sin, 0xab, sizeof(struct sockaddr_in));
  struct sockaddr_storage sas;
  int result = net_getpeername(socket, &sas);
  if (result < 0) return result;
  if (sas.sa_family == AF_INET) {
    kmemcpy(sin, &sas, sizeof(struct sockaddr_in));
  }
  return 0;
}

static const char* getsockname_str(int socket) {
  struct sockaddr_storage sas;
  int result = net_getsockname(socket, &sas);
  if (result < 0) return errorname(-result);
  return sas2str(&sas);
}

static const char* getpeername_str(int socket) {
  struct sockaddr_storage sas;
  int result = net_getpeername(socket, &sas);
  if (result < 0) return errorname(-result);
  return sas2str(&sas);
}

static int do_setsockopt_int(int socket, int domain, int option, int val) {
  return net_setsockopt(socket, domain, option, &val, sizeof(int));
}

static const char* get_sock_state_r(int socket, char* buf, socklen_t len) {
  buf[0] = '\0';
  int result = net_getsockopt(socket, IPPROTO_TCP, SO_TCP_SOCKSTATE, buf, &len);
  KEXPECT_EQ(0, result);
  return buf;
}

static const char* get_sock_state(int socket) {
  static char buf[40];
  socklen_t len = 40;
  return get_sock_state_r(socket, buf, len);
}

// Force a socket that is in TIME_WAIT to close.
static void kill_time_wait(int socket) {
  char buf[40];
  socklen_t len = 40;
  KEXPECT_STREQ("TIME_WAIT", get_sock_state_r(socket, buf, len));
  KEXPECT_EQ(0,
             do_setsockopt_int(socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 0));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state_r(socket, buf, len));
}

static void close_time_wait(int socket) {
  kill_time_wait(socket);
  KEXPECT_EQ(0, vfs_close(socket));
}

static tcp_key_t tcp_key_sin(const struct sockaddr_in* a,
                             const struct sockaddr_in* b) {
  return tcp_key((const struct sockaddr*)a, (const struct sockaddr*)b);
}

static tcp_key_t tcp_key_sin6(const struct sockaddr_in6* a,
                              const struct sockaddr_in6* b) {
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

  KEXPECT_EQ(tcp_key_single((struct sockaddr*)&src1),
             tcp_key_single((struct sockaddr*)&src2));
  KEXPECT_EQ(tcp_key_single((struct sockaddr*)&dst1),
             tcp_key_single((struct sockaddr*)&dst2));
  KEXPECT_NE(tcp_key_single((struct sockaddr*)&src1),
             tcp_key_single((struct sockaddr*)&dst1));

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
  tcp_key_t orig_single = tcp_key_single((struct sockaddr*)&src2);
  src2.sin_addr.s_addr++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  KEXPECT_NE(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2 = src1;

  KEXPECT_EQ(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2.sin_port++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  KEXPECT_NE(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2 = src1;

  dst2.sin_addr.s_addr++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  dst2 = dst1;

  dst2.sin_port++;
  KEXPECT_NE(orig, tcp_key_sin(&src2, &dst2));
  dst2 = dst1;
}

static void tcp_v6_key_test(void) {
  KTEST_BEGIN("TCP key test (AF_INET6)");
  struct sockaddr_in6 src1, src2, dst1, dst2;
  kmemset(&src1, 0xaa, sizeof(src1));
  kmemset(&src2, 0xbb, sizeof(src2));
  kmemset(&dst1, 0xcc, sizeof(dst1));
  kmemset(&dst2, 0xdd, sizeof(dst2));
  src1.sin6_family = src2.sin6_family = dst1.sin6_family = dst2.sin6_family =
      AF_INET6;
  KEXPECT_NE(tcp_key_sin6(&src1, &dst1), tcp_key_sin6(&src2, &dst2));
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &src1.sin6_addr));
  src1.sin6_port = 1;
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &dst1.sin6_addr));
  dst1.sin6_port = 2;
  KEXPECT_EQ(0, str2inet6("2001:db8::1", &src2.sin6_addr));
  src2.sin6_port = 1;
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &dst2.sin6_addr));
  dst2.sin6_port = 2;
  KEXPECT_EQ(tcp_key_sin6(&src1, &dst1), tcp_key_sin6(&src2, &dst2));
  KEXPECT_EQ(tcp_key_sin6(&src2, &dst1), tcp_key_sin6(&src1, &dst2));
  KEXPECT_EQ(tcp_key_sin6(&src1, &dst2), tcp_key_sin6(&src2, &dst1));

  KEXPECT_NE(tcp_key_sin6(&src1, &dst1), tcp_key_sin6(&dst1, &src1));

  KEXPECT_EQ(tcp_key_single((struct sockaddr*)&src1),
             tcp_key_single((struct sockaddr*)&src2));
  KEXPECT_EQ(tcp_key_single((struct sockaddr*)&dst1),
             tcp_key_single((struct sockaddr*)&dst2));
  KEXPECT_NE(tcp_key_single((struct sockaddr*)&src1),
             tcp_key_single((struct sockaddr*)&dst1));

  src1 = src2;
  src1.sin6_port = 2;
  KEXPECT_NE(tcp_key_sin6(&src1, &dst1), tcp_key_sin6(&src2, &dst2));
  src1 = src2;
  KEXPECT_EQ(0, str2inet6("2001:db8::2", &src1.sin6_addr));
  KEXPECT_NE(tcp_key_sin6(&src1, &dst1), tcp_key_sin6(&src2, &dst2));

  // Test sensitivity to different elements of the address.
  src2 = src1;
  dst2 = dst1;
  tcp_key_t orig = tcp_key_sin6(&src2, &dst2);
  tcp_key_t orig_single = tcp_key_single((struct sockaddr*)&src2);
  src2.sin6_addr.s6_addr[0]++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_NE(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2 = src1;

  KEXPECT_EQ(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_EQ(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2.sin6_addr.s6_addr[8]++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_NE(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2 = src1;

  KEXPECT_EQ(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_EQ(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2.sin6_addr.s6_addr[15]++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_NE(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2 = src1;

  KEXPECT_EQ(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_EQ(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2.sin6_port++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  KEXPECT_NE(orig_single, tcp_key_single((struct sockaddr*)&src2));
  src2 = src1;

  dst2.sin6_addr.s6_addr[0]++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  dst2 = dst1;

  KEXPECT_EQ(orig, tcp_key_sin6(&src2, &dst2));
  dst2.sin6_addr.s6_addr[8]++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  dst2 = dst1;

  KEXPECT_EQ(orig, tcp_key_sin6(&src2, &dst2));
  dst2.sin6_addr.s6_addr[15]++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
  dst2 = dst1;

  KEXPECT_EQ(orig, tcp_key_sin6(&src2, &dst2));
  dst2.sin6_port++;
  KEXPECT_NE(orig, tcp_key_sin6(&src2, &dst2));
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
  KEXPECT_EQ(-ENOPROTOOPT,
             net_setsockopt(sock, SOL_SOCKET, SO_ERROR, &val[0], vallen));

  KTEST_BEGIN("TCP: SO_TCP_TIME_WAIT_LEN invalid value");
  KEXPECT_EQ(0,
             do_setsockopt_int(sock, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 400));
  KEXPECT_EQ(-EINVAL,
             do_setsockopt_int(sock, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, -1));
  KEXPECT_EQ(-EINVAL,
             do_setsockopt_int(sock, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, -400));
  KEXPECT_EQ(-EINVAL,
             do_setsockopt_int(sock, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 0));
  int val_int;
  len = sizeof(int);
  KEXPECT_EQ(0, net_getsockopt(sock, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN,
                               &val_int, &len));
  KEXPECT_EQ(sizeof(int), len);
  KEXPECT_EQ(400, val_int);

  KEXPECT_EQ(0, vfs_close(sock));
}

static void bind_test(void) {
  KTEST_BEGIN("getsockname(SOCK_STREAM): unbound socket");
  int sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  struct sockaddr_storage result_addr_storage;
  struct sockaddr_in* result_addr = (struct sockaddr_in*)&result_addr_storage;
  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(INADDR_ANY, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(INET_PORT_ANY, result_addr->sin_port);

  KTEST_BEGIN("getpeername(SOCK_STREAM): unbound socket");
  KEXPECT_EQ(-ENOTCONN, net_getpeername(sock, &result_addr_storage));

  KTEST_BEGIN("bind(SOCK_STREAM): can bind to NIC's address");
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  netaddr_t netaddr;
  KEXPECT_GE(inet_choose_bind(ADDR_INET, &netaddr), 0);
  KEXPECT_EQ(0, net2sockaddr(&netaddr, 0, &addr, sizeof(addr)));
  addr.sin_port = 1234;

  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("getsockname(SOCK_STREAM): bound socket");
  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_EQ(addr.sin_addr.s_addr, result_addr->sin_addr.s_addr);
  KEXPECT_EQ(1234, result_addr->sin_port);

  KTEST_BEGIN("getpeername(SOCK_STREAM): bound socket");
  KEXPECT_EQ(-ENOTCONN, net_getpeername(sock, &result_addr_storage));

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

  addr.sin_family = AF_INET6;
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
  addr.sin_addr.s_addr = str2inet(SRC_IP);
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

  addr.sin_addr.s_addr = str2inet(SRC_IP);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("bind(SOCK_STREAM): bind to port 0 (specific IP)");
  addr.sin_addr.s_addr = str2inet(SRC_IP);
  addr.sin_port = 0;
  KEXPECT_EQ(0, vfs_close(sock));
  sock = net_socket(AF_INET, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  struct sockaddr_storage sockname_addr;
  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &sockname_addr));
  KEXPECT_STREQ(SRC_IP, sas_ip2str(&sockname_addr));
  in_port_t port1 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port1);

  KEXPECT_EQ(0, net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock2, &sockname_addr));
  KEXPECT_STREQ(SRC_IP, sas_ip2str(&sockname_addr));
  in_port_t port2 = ((struct sockaddr_in*)&sockname_addr)->sin_port;
  KEXPECT_NE(0, port2);
  KEXPECT_NE(port1, port2);

  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_close(sock2));
}

#define DEFAULT_WNDSIZE 8000

// To save stack space.  Max size of "255.255.255.255:65536" (22)
#define SOCKADDR_IN_PRETTY_LEN 30

typedef struct {
  kthread_t thread;
  int fd;
  int result;
  notification_t started;
  notification_t done;

  const char* arg_addr;
  void* arg_buffer;
  size_t arg_buflen;
  int arg_port;
  short events;
} async_op_t;

typedef struct {
  int socket;
  async_op_t op;

  // Address of the TCP socket under test.
  const char* tcp_addr_str;
  struct sockaddr_storage_ip tcp_addr;

  // Raw socket and buffer for the "other side".
  char raw_addr_str[SOCKADDR_IN_PRETTY_LEN];
  struct sockaddr_storage_ip raw_addr;
  char recv[RAW_RECV_BUF_SIZE];

  // Window size to send when not otherwise specified.
  size_t wndsize;

  // Sequence base for the socket.
  uint32_t seq_base;
  uint32_t send_seq_base;

  // Expected flow label for incoming packets.
  uint32_t flow_label;
} tcp_test_state_t;

// Creates and initializes the test state.  Does _not_ bind the test socket.
// Multiple test states may be used in the same test simultaneously to test
// different sockets simultaneously --- the raw recv sockets should each bind to
// a different IP, however, or each will get packets sent by all test sockets.
static void init_tcp_test(tcp_test_state_t* s, const char* tcp_addr,
                          int tcp_port, const char* dst_addr, int dst_port) {
  s->tcp_addr_str = tcp_addr;
  make_saddr(&s->tcp_addr, tcp_addr, tcp_port);

  s->wndsize = DEFAULT_WNDSIZE;
  s->seq_base = g_tcp_test.seq_start;
  s->send_seq_base = g_tcp_test.seq_start + 100 - 500;
  s->flow_label = 0;
  s->socket = net_socket(s->tcp_addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
  s->op.thread = NULL;
  KEXPECT_GE(s->socket, 0);

  KEXPECT_EQ(0, set_initial_seqno(s->socket, s->seq_base + 100));

  if (dst_addr) {
    kstrcpy(s->raw_addr_str, dst_addr);
    make_saddr(&s->raw_addr, dst_addr, dst_port);
  } else {
    s->raw_addr_str[0] = '\0';
  }
}

// Creates a TCP test state for a child socket returned by accept().
static void init_tcp_test_child(const tcp_test_state_t* parent,
                                tcp_test_state_t* s, const char* dst_addr,
                                int dst_port) {
  s->wndsize = parent->wndsize;
  s->seq_base = g_tcp_test.seq_start;
  s->send_seq_base = g_tcp_test.seq_start + 100 - 500;
  s->flow_label = 0;
  s->socket = -1;
  s->op.thread = NULL;

  s->tcp_addr_str = parent->tcp_addr_str;
  s->tcp_addr = parent->tcp_addr;

  kstrcpy(s->raw_addr_str, dst_addr);
  make_saddr(&s->raw_addr, dst_addr, dst_port);
}

static int raw_drain_packets(tcp_test_state_t* s);

static void cleanup_tcp_test(tcp_test_state_t* s) {
  if (s->socket >= 0) {
    KEXPECT_EQ(0, vfs_close(s->socket));
  }
  // TODO(aoates): consider having this KEXPECT_EQ(0, ...) and update all tests
  // to actually expect all the packets that they generate.
  raw_drain_packets(s);
  KASSERT(s->op.thread == NULL);
}

static void* tcp_thread_connect(void* arg) {
  async_op_t* op = (async_op_t*)arg;
  ntfn_notify(&op->started);
  op->result = do_connect(op->fd, op->arg_addr, op->arg_port);
  ntfn_notify(&op->done);
  return NULL;
}

// Start an async connect() call in another thread and ensure it blocks.  The
// test should either manually finish the connect call (with the SYN/SYN-ACK/ACK
// sequence, or a variant), or call finish_standard_connect() below.
static bool start_connect(tcp_test_state_t* s, const char* ip, int port) {
  ntfn_init(&s->op.started);
  ntfn_init(&s->op.done);
  s->op.fd = s->socket;
  s->op.arg_addr = ip;
  s->op.arg_port = port;
  KEXPECT_EQ(0, proc_thread_create(&s->op.thread, &tcp_thread_connect, &s->op));
  if (!ntfn_await_with_timeout(&s->op.started, 5000)) {
    KTEST_ADD_FAILURE("connect() thread didn't start");
    return false;
  }
  if (ntfn_has_been_notified(&s->op.done)) {
    KTEST_ADD_FAILURE("connect() finished without blocking");
    KEXPECT_EQ(0, s->op.result);  // Get the error code.
    return false;
  }
  return true;
}

static void* tcp_thread_read(void* arg) {
  async_op_t* op = (async_op_t*)arg;
  ntfn_notify(&op->started);
  op->result = vfs_read(op->fd, op->arg_buffer, op->arg_buflen);
  ntfn_notify(&op->done);
  return NULL;
}

// Start an async read() call in another thread and ensure it blocks.
static bool start_read_op(async_op_t* op, void* buf, size_t buflen) {
  kmemset(buf, 0, buflen);
  ntfn_init(&op->started);
  ntfn_init(&op->done);
  op->arg_buffer = buf;
  op->arg_buflen = buflen;
  KEXPECT_EQ(0, proc_thread_create(&op->thread, &tcp_thread_read, op));
  if (!ntfn_await_with_timeout(&op->started, 5000)) {
    KTEST_ADD_FAILURE("read() thread didn't start");
    return false;
  }
  if (ntfn_has_been_notified(&op->done)) {
    KTEST_ADD_FAILURE("read() finished without blocking");
    KEXPECT_EQ(0, op->result);  // Get the error code.
    return false;
  }
  return true;
}

static bool start_read(tcp_test_state_t* s, void* buf, size_t buflen) {
  s->op.fd = s->socket;
  return start_read_op(&s->op, buf, buflen);
}

static void* tcp_thread_write(void* arg) {
  async_op_t* op = (async_op_t*)arg;
  ntfn_notify(&op->started);

  // Block SIGPIPE in _this_ thread --- that way, if it's generated, it can be
  // detected from the test thread even if this one exits.
  ksigset_t block;
  ksigemptyset(&block);
  ksigaddset(&block, SIGPIPE);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &block, NULL));

  op->result = vfs_write(op->fd, op->arg_buffer, op->arg_buflen);
  ntfn_notify(&op->done);
  return NULL;
}

// Start an async write() call in another thread and ensure it blocks.
static bool start_write(tcp_test_state_t* s, const char* data) {
  ntfn_init(&s->op.started);
  ntfn_init(&s->op.done);
  s->op.fd = s->socket;
  s->op.arg_buffer = (void*)data;
  s->op.arg_buflen = kstrlen(data);
  KEXPECT_EQ(0, proc_thread_create(&s->op.thread, &tcp_thread_write, &s->op));
  if (!ntfn_await_with_timeout(&s->op.started, 5000)) {
    KTEST_ADD_FAILURE("write() thread didn't start");
    return false;
  }
  if (ntfn_has_been_notified(&s->op.done)) {
    KTEST_ADD_FAILURE("write() finished without blocking");
    KEXPECT_EQ(0, s->op.result);  // Get the error code.
    return false;
  }
  return true;
}

static void* tcp_thread_accept(void* arg) {
  async_op_t* op = (async_op_t*)arg;
  ntfn_notify(&op->started);
  op->result = net_accept(op->fd, NULL, NULL);
  ntfn_notify(&op->done);
  return NULL;
}

static bool start_accept(tcp_test_state_t* s) {
  ntfn_init(&s->op.started);
  ntfn_init(&s->op.done);
  s->op.fd = s->socket;
  KEXPECT_EQ(0, proc_thread_create(&s->op.thread, &tcp_thread_accept, &s->op));
  if (!ntfn_await_with_timeout(&s->op.started, 5000)) {
    KTEST_ADD_FAILURE("accept() thread didn't start");
    return false;
  }
  if (ntfn_has_been_notified(&s->op.done)) {
    KTEST_ADD_FAILURE("accept() finished without blocking");
    KEXPECT_EQ(0, s->op.result);  // Get the error code.
    return false;
  }
  return true;
}

static void* tcp_thread_poll(void* arg) {
  async_op_t* op = (async_op_t*)arg;
  ntfn_notify(&op->started);
  struct apos_pollfd pfd;
  pfd.fd = op->fd;
  pfd.events = op->events;
  pfd.revents = 0;
  op->result = vfs_poll(&pfd, 1, 2000);
  op->events = pfd.revents;
  ntfn_notify(&op->done);
  return NULL;
}

static bool start_poll(async_op_t* op, int fd, short events) {
  ntfn_init(&op->started);
  ntfn_init(&op->done);
  op->fd = fd;
  op->events = events;
  KEXPECT_EQ(0, proc_thread_create(&op->thread, &tcp_thread_poll, op));
  if (!ntfn_await_with_timeout(&op->started, 5000)) {
    KTEST_ADD_FAILURE("poll() thread didn't start");
    return false;
  }
  if (ntfn_has_been_notified(&op->done)) {
    KTEST_ADD_FAILURE("poll() finished without blocking");
    KEXPECT_EQ(0, op->result);  // Get the error code.
    return false;
  }
  return true;
}

static int finish_op_direct(async_op_t* op) {
  bool finished = ntfn_await_with_timeout(&op->done, 5000);
  KEXPECT_EQ(true, finished);
  if (!finished) return -ETIMEDOUT;

  KEXPECT_EQ(NULL, kthread_join(op->thread));
  op->thread = NULL;
  return op->result;
}

static int finish_op(tcp_test_state_t* s) {
  return finish_op_direct(&s->op);
}

// Assumes that no one will alter the packet list in the meantime.
static bool raw_has_packets_wait(tcp_test_state_t* s, int timeout_ms) {
  if (!list_empty(&g_tcp_test.packets)) {
    return true;
  }
  return socket_has_data(g_tcp_test.tun_fd, timeout_ms);
}

static bool raw_has_packets(tcp_test_state_t* s) {
  return raw_has_packets_wait(s, 0);
}

// Reads all packets from the TUN fd into the queue.
static void read_tun_packets(void) {
  while (true) {
    queued_packet_t* pkt = KMALLOC(queued_packet_t);
    int result = vfs_read(g_tcp_test.tun_fd, pkt->packet, RAW_RECV_BUF_SIZE);
    if (result == -EAGAIN) {
      kfree(pkt);
      return;
    }

    int version = ((uint8_t*)pkt->packet)[0] >> 4;
    tcp_hdr_t* tcp_hdr = NULL;
    if (version == 4) {
      const ip4_hdr_t* ip4_hdr = (const ip4_hdr_t*)&pkt->packet;
      pkt->dst_ip.sa_family = AF_INET;
      ((struct sockaddr_in*)&pkt->dst_ip)->sin_addr.s_addr = ip4_hdr->dst_addr;
      KASSERT(ip4_hdr->protocol == IPPROTO_TCP);
      tcp_hdr =
          (tcp_hdr_t*)(&pkt->packet[ip4_ihl(*ip4_hdr) * sizeof(uint32_t)]);
    } else {
      KASSERT(version == 6);
      const ip6_hdr_t* ip6_hdr = (const ip6_hdr_t*)&pkt->packet;
      struct sockaddr_in6* pkt_v6 = (struct sockaddr_in6*)&pkt->dst_ip;
      pkt_v6->sin6_family = AF_INET6;
      pkt_v6->sin6_scope_id = 0;
      kmemcpy(&pkt_v6->sin6_addr, &ip6_hdr->dst_addr, sizeof(struct in6_addr));
      KASSERT(ip6_hdr->next_hdr == IPPROTO_TCP);
      tcp_hdr = (tcp_hdr_t*)(&pkt->packet[sizeof(ip6_hdr_t)]);
    }
    set_sockaddrs_port((struct sockaddr_storage*)&pkt->dst_ip,
                       btoh16(tcp_hdr->dst_port));
    pkt->link = LIST_LINK_INIT;
    pkt->packet_len = result;
    list_push(&g_tcp_test.packets, &pkt->link);
  }
}

// Drains all pending packets from the TUN device, returning the number of
// packets removed.  Doesn't filter by IP address.
static int raw_drain_packets(tcp_test_state_t* s) {
  read_tun_packets();
  int result = 0;
  while (!list_empty(&g_tcp_test.packets)) {
    list_link_t* link = list_pop(&g_tcp_test.packets);
    queued_packet_t* pkt = container_of(link, queued_packet_t, link);
    kfree(pkt);
    result++;
  }
  return result;
}

static ssize_t do_raw_recv(tcp_test_state_t* s) {
  read_tun_packets();
  FOR_EACH_LIST(list_iter, &g_tcp_test.packets) {
    queued_packet_t* pkt = LIST_ENTRY(list_iter, queued_packet_t, link);
    if (sockaddr_equal((struct sockaddr*)&pkt->dst_ip,
                       (struct sockaddr*)&s->raw_addr)) {
      list_remove(&g_tcp_test.packets, &pkt->link);
      kmemcpy(s->recv, pkt->packet, RAW_RECV_BUF_SIZE);
      if (pkt->packet_len < RAW_RECV_BUF_SIZE) {
        kmemset((char*)&s->recv + pkt->packet_len, 0,
                RAW_RECV_BUF_SIZE - pkt->packet_len);
      }
      ssize_t result = pkt->packet_len;
      kfree(pkt);
      return result;
    }
  }
  KTEST_ADD_FAILURE("Raw socket has no packets available");
  return -EAGAIN;
}

static ssize_t do_raw_send(tcp_test_state_t* s, const void* buf, size_t len) {
  pbuf_t* pb = pbuf_create(INET6_HEADER_RESERVE, len);
  KASSERT(pb);

  kmemcpy(pbuf_get(pb), buf, len);
  if (s->raw_addr.sa_family == AF_INET) {
    const struct sockaddr_in* raw = (const struct sockaddr_in*)&s->raw_addr;
    const struct sockaddr_in* dst = (const struct sockaddr_in*)&s->tcp_addr;
    ip4_add_hdr(pb, raw->sin_addr.s_addr, dst->sin_addr.s_addr, IPPROTO_TCP);
  } else {
    KASSERT_DBG(s->raw_addr.sa_family == AF_INET6);
    KASSERT_DBG(s->tcp_addr.sa_family == AF_INET6);
    const struct sockaddr_in6* raw = (const struct sockaddr_in6*)&s->raw_addr;
    const struct sockaddr_in6* dst = (const struct sockaddr_in6*)&s->tcp_addr;
    ip6_add_hdr(pb, &raw->sin6_addr, &dst->sin6_addr, IPPROTO_TCP, 0);
  }

  ssize_t result = g_tcp_test.tun_chardev->write(
      g_tcp_test.tun_chardev, pbuf_getc(pb), pbuf_size(pb), 0);
  if (result > 0) {
    result -= (pbuf_size(pb) - len);
  }
  pbuf_free(pb);
  return result;
}

// Special value to indicate a zero window size (since passing zero means
// "ignore").
#define WNDSIZE_ZERO 0xabcd
#define FLOW_LABEL_ZERO 0xabcd

// Specification for a packet to expect or send.  Fields not supplied are not
// checked (on receive), or given default values (on send).
typedef struct {
  int flags;
  uint32_t seq;
  uint32_t ack;
  int wndsize;
  const char* data;
  size_t datalen;
  bool literal_seq;
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
  KASSERT_DBG(wndsize != 0);  // Must send WNDSIZE_ZERO.
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
  return ((test_packet_spec_t){.flags = TCP_FLAG_RST | TCP_FLAG_ACK,
                               .seq = seq,
                               .ack = ack,
                               .literal_seq = (seq == 0)});
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

static test_packet_spec_t DATA_PKT2(int seq, int ack, int wndsize,
                                    const char* data) {
  KASSERT_DBG(wndsize != 0);  // Must send WNDSIZE_ZERO.
  return ((test_packet_spec_t){.flags = TCP_FLAG_ACK,
                               .seq = seq,
                               .ack = ack,
                               .wndsize = wndsize,
                               .data = data,
                               .datalen = kstrlen(data)});
}

static test_packet_spec_t URG_PKT(int seq, int ack, const char* data) {
  return ((test_packet_spec_t){.flags = TCP_FLAG_ACK | TCP_FLAG_URG,
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

static test_packet_spec_t SYN_DATA_PKT(int seq, int ack, const char* data) {
  test_packet_spec_t result = DATA_PKT(seq, ack, data);
  result.flags |= TCP_FLAG_SYN;
  return result;
}

static test_packet_spec_t NOACK(test_packet_spec_t p) {
  p.flags &= ~TCP_FLAG_ACK;
  return p;
}

#define EXPECT_PKT(_state, _spec) KEXPECT_TRUE(receive_pkt(_state, _spec))
#define SEND_PKT(_state, _spec) KEXPECT_TRUE(build_send_pkt(_state, _spec))

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
  size_t header_len = 0;
  if (s->raw_addr.sa_family == AF_INET) {
    v &= KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t) + spec.datalen,
                    result);
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
    header_len = sizeof(ip4_hdr_t);
  } else {
    KASSERT_DBG(s->raw_addr.sa_family == AF_INET6);
    v &= KEXPECT_EQ(sizeof(ip6_hdr_t) + sizeof(tcp_hdr_t) + spec.datalen,
                    result);
    if (result < (int)sizeof(ip6_hdr_t) + (int)sizeof(tcp_hdr_t)) {
      return false;
    }

    ip6_hdr_t* ip_hdr = (ip6_hdr_t*)s->recv;
    v &= KEXPECT_EQ(6, ip6_version(*ip_hdr));
    v &= KEXPECT_EQ(0, ip6_traffic_class(*ip_hdr));
    if (s->flow_label == FLOW_LABEL_ZERO) {
      v &= KEXPECT_EQ(0, ip6_flow(*ip_hdr));
    } else if (s->flow_label != 0) {
      v &= KEXPECT_EQ(s->flow_label, ip6_flow(*ip_hdr));
    } else if (!(spec.flags & TCP_FLAG_RST)) {
      // Make sure the flow label is set to _something_ in most tests.  The flow
      // label should be set on _some_ RSTs, but hard to tell here, so don't
      // bother as this is a catchall.
      v &= KEXPECT_NE(0, ip6_flow(*ip_hdr));
    }
    v &= KEXPECT_EQ(result, sizeof(ip6_hdr_t) + btoh16(ip_hdr->payload_len));
    v &= KEXPECT_EQ(IPPROTO_TCP, ip_hdr->next_hdr);
    // Don't bother checking the checksum here.
    char addrstr[INET6_PRETTY_LEN];
    v &= KEXPECT_STREQ(s->tcp_addr_str, inet62str(&ip_hdr->src_addr, addrstr));
    v &= KEXPECT_STREQ(s->raw_addr_str, inet62str(&ip_hdr->dst_addr, addrstr));
    header_len = sizeof(ip6_hdr_t);
  }

  // Validate the TCP header.
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)&s->recv[header_len];
  v &= KEXPECT_EQ(get_sockaddrs_port((struct sockaddr_storage*)&s->tcp_addr),
                  btoh16(tcp_hdr->src_port));
  v &= KEXPECT_EQ(get_sockaddrs_port((struct sockaddr_storage*)&s->raw_addr),
                  btoh16(tcp_hdr->dst_port));
  if (spec.literal_seq) {
    v &= KEXPECT_EQ(spec.seq, btoh32(tcp_hdr->seq));
  } else {
    v &= KEXPECT_EQ(spec.seq, btoh32(tcp_hdr->seq) - s->seq_base);
  }
  if (spec.flags & TCP_FLAG_ACK) {
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
    KEXPECT_STREQ(spec.data, s->recv + header_len + sizeof(tcp_hdr_t));
  }
  return v;
}

// (re)calculates the TCP header checksum for the packet.
static void calc_checksum(tcp_test_state_t* s, pbuf_t* pb) {
  void* pseudo_ip = NULL;
  size_t pseudo_ip_size = 0;
  ip4_pseudo_hdr_t pseudo_ip_v4;
  ip6_pseudo_hdr_t pseudo_ip_v6;
  size_t tcp_len = pbuf_size(pb);
  if (s->raw_addr.sa_family == AF_INET) {
    pseudo_ip = &pseudo_ip_v4;
    pseudo_ip_size = sizeof(pseudo_ip_v4);

    pseudo_ip_v4.src_addr =
        ((struct sockaddr_in*)&s->raw_addr)->sin_addr.s_addr;
    pseudo_ip_v4.dst_addr =
        ((struct sockaddr_in*)&s->tcp_addr)->sin_addr.s_addr;
    pseudo_ip_v4.zeroes = 0;
    pseudo_ip_v4.protocol = IPPROTO_TCP;
    pseudo_ip_v4.length = btoh16(tcp_len);
  } else {
    KASSERT_DBG(s->raw_addr.sa_family == AF_INET6);
    pseudo_ip = &pseudo_ip_v6;
    pseudo_ip_size = sizeof(pseudo_ip_v6);

    pseudo_ip_v6.src_addr = ((struct sockaddr_in6*)&s->raw_addr)->sin6_addr;
    pseudo_ip_v6.dst_addr = ((struct sockaddr_in6*)&s->tcp_addr)->sin6_addr;
    kmemset(&pseudo_ip_v6._zeroes, 0, 3);
    pseudo_ip_v6.next_hdr = IPPROTO_TCP;
    pseudo_ip_v6.payload_len = btoh16(tcp_len);
  }

  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pb);
  tcp_hdr->checksum = 0;
  tcp_hdr->checksum =
      ip_checksum2(pseudo_ip, pseudo_ip_size, tcp_hdr, tcp_len);
}

// Builds a packet based on the given spec.
static pbuf_t* build_pkt(tcp_test_state_t* s, test_packet_spec_t spec) {
  pbuf_t* pb = pbuf_create(0, sizeof(tcp_hdr_t) + spec.datalen);
  void* buf = pbuf_get(pb);
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)buf;
  kmemset(tcp_hdr, 0, sizeof(tcp_hdr_t));
  tcp_hdr->src_port =
      htob16(get_sockaddrs_port((struct sockaddr_storage*)&s->raw_addr));
  tcp_hdr->dst_port =
      htob16(get_sockaddrs_port((struct sockaddr_storage*)&s->tcp_addr));
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

  calc_checksum(s, pb);
  return pb;
}

static bool send_pkt(tcp_test_state_t* s, pbuf_t* pb) {
  bool result =
      KEXPECT_EQ(pbuf_size(pb), do_raw_send(s, pbuf_get(pb), pbuf_size(pb)));
  pbuf_free(pb);
  return result;
}

// Builds a packet based on the given spec and sends it.
static bool build_send_pkt(tcp_test_state_t* s, test_packet_spec_t spec) {
  return send_pkt(s, build_pkt(s, spec));
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

// Do a "connect" operation on a child test state.
static void do_child_connect(const tcp_test_state_t* parent,
                             tcp_test_state_t* child, const char* dst_addr,
                             int dst_port, uint32_t seq) {
  init_tcp_test_child(parent, child, dst_addr, dst_port);

  SEND_PKT(child, SYN_PKT(/* seq */ seq, /* wndsize */ 8000));
  EXPECT_PKT(child,
             SYNACK_PKT(/* seq */ 100, /* ack */ seq + 1, /* wnd */ 16384));
  SEND_PKT(child, ACK_PKT(/* seq */ seq + 1, /* ack */ 101));

  char addr[SOCKADDR_PRETTY_LEN];
  char expected[SOCKADDR_PRETTY_LEN];
  ksprintf(expected, "%s:%d", dst_addr, dst_port);
  child->socket = do_accept(parent->socket, addr);
  KEXPECT_GE(child->socket, 0);
  KEXPECT_STREQ(expected, addr);
}

static void basic_connect_test(void) {
  KTEST_BEGIN("TCP: basic connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  s.seq_base = s.send_seq_base = 0;
  KEXPECT_EQ(0, set_initial_seqno(s.socket, 100));
  KEXPECT_STREQ("CLOSED", get_sock_state(s.socket));

  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, "2001:db8::1", 0x1234));
  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, "2001:db8::2", 0x1234));
  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, "::1", 0x1234));
  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, "::", 0x1234));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  KEXPECT_EQ(0x7acd, btoh16(ip_hdr->hdr_checksum));
  KEXPECT_STREQ(SRC_IP, ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ(DST_IP, ip2str(ip_hdr->dst_addr));

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
  KEXPECT_EQ(0x6cf, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  // Send SYN-ACK back.  Raw socket will make the IP header for us.
  tcp_hdr->src_port = btoh16(0x5678);
  tcp_hdr->dst_port = btoh16(0x1234);
  tcp_hdr->seq = btoh32(0x1000);
  tcp_hdr->ack = btoh32(101);
  tcp_hdr->checksum = 0x7e17;
  tcp_hdr->flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
  tcp_hdr->wndsize = btoh16(8000);
  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

  // Should get an ACK.
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_STREQ(SRC_IP, ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ(DST_IP, ip2str(ip_hdr->dst_addr));

  // Validate the TCP header.
  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1001, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf6be, btoh16(tcp_hdr->checksum));
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
  tcp_hdr->checksum = 0x9ef6;

  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  KEXPECT_TRUE(raw_has_packets(&s));
  result = do_raw_recv(&s);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(tcp_hdr_t), result);
  KEXPECT_EQ(IPPROTO_TCP, ip_hdr->protocol);
  KEXPECT_STREQ(SRC_IP, ip2str(ip_hdr->src_addr));
  KEXPECT_STREQ(DST_IP, ip2str(ip_hdr->dst_addr));

  KEXPECT_EQ(0x1234, btoh16(tcp_hdr->src_port));
  KEXPECT_EQ(0x5678, btoh16(tcp_hdr->dst_port));
  KEXPECT_EQ(101, btoh32(tcp_hdr->seq));
  KEXPECT_EQ(0x1002, btoh32(tcp_hdr->ack));
  KEXPECT_EQ(0, tcp_hdr->_zeroes);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  KEXPECT_EQ(TCP_FLAG_ACK, tcp_hdr->flags);
  KEXPECT_EQ(16384, btoh16(tcp_hdr->wndsize));
  KEXPECT_EQ(0xf6bd, btoh16(tcp_hdr->checksum));
  KEXPECT_EQ(0, btoh16(tcp_hdr->urg_ptr));

  char buf;
  KEXPECT_EQ(0, vfs_read(s.socket, &buf, 1));

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
  KEXPECT_EQ(0xf6bc, btoh16(tcp_hdr->checksum));
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
  tcp_hdr->checksum = 0x9df6;
  KEXPECT_EQ(sizeof(tcp_hdr_t), do_raw_send(&s, tcp_hdr, sizeof(tcp_hdr_t)));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void basic_connect_test2(void) {
  KTEST_BEGIN("TCP: basic connect() (v2)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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

static void urg_resets_connection(void) {
  KTEST_BEGIN("TCP: URG resets connection");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, URG_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  char buf;
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, &buf, 1));

  cleanup_tcp_test(&s);
}

static void bad_packets_syn_sent_test(void) {
  KTEST_BEGIN("TCP: various bad packets sent in SYN_SENT");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  set_rto(s.socket, 10000);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Send plain ACKs --- these should cause RSTs.
  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 100));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 100));
  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 90));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 90));
  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 102));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 102));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Next try SYN/ACKs, but where the ACK value is incorrect.  These should get
  // RSTs as well.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 100, /* wndsize */ 8000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 100));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 90, /* wndsize */ 8000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 90));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 102, /* wndsize */ 8000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 102));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Now try RST+ACKs (with bad ACK).  These should be ignored.
  SEND_PKT(&s, RST_PKT(/* seq */ 500, /* ack */ 100));
  SEND_PKT(&s, RST_PKT(/* seq */ 500, /* ack */ 90));
  SEND_PKT(&s, RST_PKT(/* seq */ 500, /* ack */ 102));

  // A blind ACK should be ignored.
  SEND_PKT(&s, RST_NOACK_PKT(/* seq */ 500));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Now try a plain _good_ ACK with no SYN.  Should be ignored.
  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 101));
  SEND_PKT(&s, FIN_PKT(/* seq */ 500, /* ack */ 101));
  SEND_PKT(&s, DATA_PKT(/* seq */ 500, /* ack */ 101, "test"));
  SEND_PKT(&s, URG_PKT(/* seq */ 500, /* ack */ 101, "test"));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 500, /* ack */ 101, "test"));
  test_packet_spec_t pkt = FIN_PKT(/* seq */ 500, /* ack */ 101);
  pkt.flags &= ~TCP_FLAG_ACK;
  SEND_PKT(&s, pkt);
  pkt = DATA_PKT(/* seq */ 500, /* ack */ 101, "abc");
  pkt.flags &= ~TCP_FLAG_ACK;
  SEND_PKT(&s, pkt);
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));


  // After all the bad packets, we should still be able to complete the
  // connection.
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP_2, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP_2, 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNREFUSED, finish_op(&s));

  struct sockaddr_storage unused;
  KEXPECT_EQ(-EINVAL, net_getsockname(s.socket, &unused));
  KEXPECT_EQ(-EINVAL, net_getpeername(s.socket, &unused));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, SRC_IP, 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, DST_IP, 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, DST_IP_2, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, SRC_IP, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, DST_IP, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, DST_IP_2, 80));

  char buf;
  KEXPECT_EQ(0, vfs_read(s.socket, &buf, 1));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(0, get_so_error(s.socket));

  cleanup_tcp_test(&s);
}

static void multiple_connect_test(void) {
  KTEST_BEGIN("TCP: multiple connect() calls");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Try connect() while another thread is blocked in connect().
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP, 55));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, SRC_IP, 55));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP_2, 55));

  KEXPECT_TRUE(finish_standard_connect(&s));

  // Try connect() on a connected socket.
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, DST_IP, 55));
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, DST_IP_2, 55));

  // Finish up.
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void two_simultaneous_connects_test(void) {
  KTEST_BEGIN("TCP: two sockets connecting simultaneously");
  tcp_test_state_t s1, s2;
  init_tcp_test(&s1, SRC_IP, 0x1234, DST_IP, 0x5678);
  init_tcp_test(&s2, SRC_IP, 0x1235, DST_IP_2, 0x5678);
  KEXPECT_EQ(0, set_initial_seqno(s2.socket, s2.seq_base + 700));

  KEXPECT_EQ(0, do_bind(s1.socket, SRC_IP, 0x1234));

  // While we're here, validate binding another socket after the first one
  // rebinds as well.  Currently we should not be able to bind to
  // 127.0.0.1:0x1234 because s1 is using it --- but once s1 connects, we should
  // be able to.  Arguably, s2 shouldn't be allowed to until s1's connect
  // _completes_, rather than starts, but this is valid behavior IMO and simpler
  // to implement.  Whether s1's connect() succeeds (in connected sockets map)
  // or fails (state invalid, unbound), s2 bind to the same local address is OK.
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2.socket, "0.0.0.0", 0x1234));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s1, DST_IP, 0x5678));
  KEXPECT_EQ(0, do_bind(s2.socket, SRC_IP, 0x1235));
  KEXPECT_TRUE(start_connect(&s2, DST_IP_2, 0x5678));

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
  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_NE(0, result_addr->sin_port);
  in_port_t bound_port = result_addr->sin_port;

  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 100));

  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(bound_port, result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));


  sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, SRC_IP, 0));

  // See what port it chose.
  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ(SRC_IP, ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_NE(0, result_addr->sin_port);
  bound_port = result_addr->sin_port;

  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, DST_IP, 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, DST_IP_2, 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, bound_port));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, DST_IP, 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, DST_IP_2, 100));

  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ(SRC_IP, ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(bound_port, result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));


  sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 200));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 200));

  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ("0.0.0.0", ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(btoh16(100), result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));


  sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, do_bind(sock, SRC_IP, 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 0));
  KEXPECT_EQ(-EINVAL, do_bind(sock, "0.0.0.0", 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 100));
  KEXPECT_EQ(-EINVAL, do_bind(sock, SRC_IP, 200));

  KEXPECT_EQ(sizeof(struct sockaddr_in),
             net_getsockname(sock, &result_addr_storage));
  KEXPECT_EQ(AF_INET, result_addr->sin_family);
  KEXPECT_STREQ(SRC_IP, ip2str(result_addr->sin_addr.s_addr));
  KEXPECT_EQ(btoh16(100), result_addr->sin_port);
  KEXPECT_EQ(0, vfs_close(sock));
}

static void implicit_bind_test(void) {
  KTEST_BEGIN("TCP: socket implicitly binds on connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, IMPLICIT_SRC_IP, 0 /* will be chosen later */,
                IMPLICIT_DST_IP, 0x5678);

  // No bind!
  KEXPECT_TRUE(start_connect(&s, IMPLICIT_DST_IP, 0x5678));

  // Find out what we bound to.  getsockname() _during_ connect() is allowed by
  // the spec to do this.
  struct sockaddr_in bound_addr;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(IMPLICIT_SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_NE(0, bound_addr.sin_port);

  kmemcpy(&s.tcp_addr, &bound_addr, sizeof(bound_addr));

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(IMPLICIT_SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(get_sockaddrs_port((struct sockaddr_storage*)&s.tcp_addr),
             btoh16(bound_addr.sin_port));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);


  KTEST_BEGIN("TCP: socket implicitly rebinds any-addr+any-port on connect()");
  init_tcp_test(&s, IMPLICIT_SRC_IP, 0 /* will be chosen later */,
                IMPLICIT_DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "0.0.0.0", 0));
  KEXPECT_TRUE(start_connect(&s, IMPLICIT_DST_IP, 0x5678));

  // As above, find out what port was chosen.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(IMPLICIT_SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_NE(0, bound_addr.sin_port);
  kmemcpy(&s.tcp_addr, &bound_addr, sizeof(bound_addr));

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(IMPLICIT_SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(get_sockaddrs_port((struct sockaddr_storage*)&s.tcp_addr),
             btoh16(bound_addr.sin_port));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);


  // Internally this is the same as the above, since ports are picked in bind()
  // not connect(), but test for completeness.
  KTEST_BEGIN("TCP: socket implicitly rebinds $IP+any-port on connect()");
  init_tcp_test(&s, SRC_IP, 0 /* will be chosen later */, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // As above, find out what port was chosen.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_NE(0, bound_addr.sin_port);
  kmemcpy(&s.tcp_addr, &bound_addr, sizeof(bound_addr));

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(get_sockaddrs_port((struct sockaddr_storage*)&s.tcp_addr),
             btoh16(bound_addr.sin_port));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);


  // Also redundant with the any-ip/any-port, but included for completeness.
  KTEST_BEGIN("TCP: socket implicitly rebinds any-ip+$PORT on connect()");
  init_tcp_test(&s, IMPLICIT_SRC_IP, 0x1234, IMPLICIT_DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "0.0.0.0", 0x1234));
  KEXPECT_TRUE(start_connect(&s, IMPLICIT_DST_IP, 0x5678));

  // Check that the rebind happened correctly.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(IMPLICIT_SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(0x1234, btoh16(bound_addr.sin_port));

  // Now can continue with connection setup.
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Just in case, double check getsockname gives the same thing.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(IMPLICIT_SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(0x1234, btoh16(bound_addr.sin_port));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);
}

static void get_addrs_during_connect_test(void) {
  KTEST_BEGIN("TCP: getsockname()/getpeername() during connect()/close()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 3456, DST_IP, 7890);

  struct sockaddr_in addr;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ("0.0.0.0:0", sin2str(&addr));
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &addr));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 3456));
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ(SRC_IP ":3456", sin2str(&addr));
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &addr));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 7890));
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ(SRC_IP ":3456", sin2str(&addr));
  // We should not be able to get the peer name until the connect finishes.
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &addr));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ(SRC_IP ":3456", sin2str(&addr));
  KEXPECT_EQ(0, getpeername_inet(s.socket, &addr));
  KEXPECT_STREQ(DST_IP ":7890", sin2str(&addr));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_FALSE(raw_has_packets(&s));

  // The socket is still considered connected (partially).
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ(SRC_IP ":3456", sin2str(&addr));
  KEXPECT_EQ(0, getpeername_inet(s.socket, &addr));
  KEXPECT_STREQ(DST_IP ":7890", sin2str(&addr));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Arguably this shouldn't return an address anymore, but on macos it does and
  // the implementation is simpler so /shruggie.  -EINVAL would be OK.
  KEXPECT_EQ(0, getsockname_inet(s.socket, &addr));
  KEXPECT_STREQ(SRC_IP ":3456", sin2str(&addr));
  KEXPECT_EQ(-EINVAL, getpeername_inet(s.socket, &addr));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void connect_interrupted_test(void) {
  KTEST_BEGIN("TCP: connect() interrupted");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  proc_kill_thread(s.op.thread, SIGUSR1);
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

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
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  kthread_disable(s.op.thread);

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

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, 50));
  kthread_enable(s.op.thread);
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  kthread_disable(s.op.thread);

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

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, 50));
  kthread_enable(s.op.thread);
  KEXPECT_EQ(0, finish_op(&s));

  cleanup_tcp_test(&s);
}

static void shutdown_rd_during_connect(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RD) during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  char buf;
  KEXPECT_EQ(0, vfs_read(s.socket, &buf, 1));

  // Data should cause a RST.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, vfs_read(s.socket, &buf, 1));

  cleanup_tcp_test(&s);
}

static void shutdown_wr_during_connect(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_WR) during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  cleanup_tcp_test(&s);
}

static void shutdown_rdwr_during_connect(void) {
  KTEST_BEGIN("TCP: shutdown(SHUT_RDWR) during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  // Send shutdown while in connect().
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  cleanup_tcp_test(&s);
}

static void syn_bound_socket_test(void) {
  KTEST_BEGIN("TCP: get SYN on bound but unconnected socket");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  // SYNs and SYN_ACKs should get a RST.
  SEND_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 101));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 500));

  cleanup_tcp_test(&s);
}

static void simultaneous_connect_testA(void) {
  KTEST_BEGIN("TCP: simultaneous connect() #1");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  set_rto(s.socket, 10000);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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

  // Likewise with SYNs, SYN/ACKs, and SYN/ACKs with data.
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

  SEND_PKT(&s, SYN_DATA_PKT(/* seq */ 502, /* ack */ 101, "7890"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_DATA_PKT(/* seq */ 499, /* ack */ 101, "7890"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, SYN_DATA_PKT(/* seq */ 100000, /* ack */ 101, "7890"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // Data and FINs not aligned with the next sequence number should all be
  // ignored (but queued).
  SEND_PKT(&s, DATA_PKT(/* seq */ 502, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 490, /* ack */ 101, "456"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, DATA_PKT(/* seq */ 100000, /* ack */ 101, "789"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // Put the FIN far enough in the future in seq-space that we won't process it.
  SEND_PKT(&s, FIN_PKT(/* seq */ 508, /* ack */ 101));
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
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 505));
  KEXPECT_STREQ("xyz3", do_read(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 4));
  cleanup_tcp_test(&s);
}

static void simultaneous_connect_testB(void) {
  KTEST_BEGIN("TCP: simultaneous connect() #2");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  set_rto(s.socket, 10000);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // The connect() call shouldn't finish yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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

// TODO(tcp): allow send() in SYN_RCVD (and that FINs are queued after data).

static void connect_tests(void) {
  basic_connect_test();
  basic_connect_test2();
  urg_resets_connection();
  bad_packets_syn_sent_test();
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

static void rst_during_established_test1(void) {
  KTEST_BEGIN("TCP: RST during established (no data)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  char buf[10];
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  struct sockaddr_storage unused;
  KEXPECT_EQ(-EINVAL, net_getsockname(s.socket, &unused));
  KEXPECT_EQ(-EINVAL, net_getpeername(s.socket, &unused));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, SRC_IP, 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, DST_IP_2, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, SRC_IP, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, DST_IP_2, 80));

  KEXPECT_EQ(0, get_so_error(s.socket));

  cleanup_tcp_test(&s);
}

static void rst_during_established_test1b(void) {
  KTEST_BEGIN("TCP: RST during established (no data, test SO_ERROR)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));

  KEXPECT_EQ(ECONNRESET, get_so_error(s.socket));
  KEXPECT_EQ(0, get_so_error(s.socket));

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  cleanup_tcp_test(&s);
}

static void rst_during_established_test1c(void) {
  KTEST_BEGIN("TCP: RST during established (no data, test error from write)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  KEXPECT_EQ(-ECONNRESET, vfs_write(s.socket, "abc", 3));
  KEXPECT_EQ(0, get_so_error(s.socket));

  cleanup_tcp_test(&s);
}

static void rst_during_established_test2(void) {
  KTEST_BEGIN("TCP: RST during established (with data, different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  struct sockaddr_storage unused;
  KEXPECT_EQ(-EINVAL, net_getsockname(s.socket, &unused));
  KEXPECT_EQ(-EINVAL, net_getpeername(s.socket, &unused));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, DST_IP, 80));
  KEXPECT_EQ(-EINVAL, do_connect(s.socket, DST_IP_2, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, SRC_IP, 80));
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, DST_IP_2, 80));

  cleanup_tcp_test(&s);
}

static void rst_during_established_blocking_recv_test2(void) {
  KTEST_BEGIN("TCP: RST during established with blocking recv() (with data, "
              "different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.op.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 504, /* wndsize */ 497));

  // Send RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 504, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void rst_during_established_blocking_recv_test3(void) {
  KTEST_BEGIN("TCP: RST during established with blocking recv() (with data, "
              "same packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.op.thread);

  // Send RST _with data_.
  test_packet_spec_t rst_data_pkt =
      DATA_PKT(/* seq */ 501, /* ack */ 101, "abc");
  rst_data_pkt.flags |= TCP_FLAG_RST;
  SEND_PKT(&s, rst_data_pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

// There's no need for the equivalent of rst_during_established_test() because
// that's the standard FIN close that most tests exercise already.
static void fin_during_established_test2(void) {
  KTEST_BEGIN("TCP: FIN during established (with data, different packet)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.op.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Read should finish with the data.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(3, finish_op(&s));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.op.thread);

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
  kthread_enable(s.op.thread);
  KEXPECT_EQ(5, finish_op(&s));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.op.thread);

  // Send FIN _with data_.
  test_packet_spec_t fin_data_pkt =
      DATA_PKT(/* seq */ 501, /* ack */ 101, "de");
  fin_data_pkt.flags |= TCP_FLAG_FIN;
  SEND_PKT(&s, fin_data_pkt);
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Read should finish with the data.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(2, finish_op(&s));
  buf[2] = '\0';
  KEXPECT_STREQ("de", buf);

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));
  kthread_disable(s.op.thread);

  // Send RST with data and FIN.
  test_packet_spec_t rst_data_pkt =
      DATA_PKT(/* seq */ 501, /* ack */ 101, "abc");
  rst_data_pkt.flags |= TCP_FLAG_RST | TCP_FLAG_FIN;
  SEND_PKT(&s, rst_data_pkt);
  KEXPECT_FALSE(raw_has_packets_wait(&s, 20));  // Shouldn't get a response.

  // Read should finish with -ECONNRESET.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  // Subsequent reads should return EOF.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void read_after_shutdown_test(void) {
  KTEST_BEGIN("TCP: read buffered data after FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  SEND_PKT(&s, DATA_PKT(/* seq */ 505, /* ack */ 101, "d"));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "e"));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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

static void rst_after_fin_test2(void) {
  KTEST_BEGIN("TCP: RST packet after FIN (with blocking read)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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

static void rst_after_fin_test2b(void) {
  KTEST_BEGIN("TCP: RST packet after FIN (with blocking write)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_SNDBUF, 5));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(5, vfs_write(s.socket, "abcde", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  KEXPECT_TRUE(start_write(&s, "1234"));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 502));

  // We should be in CLOSE_WAIT. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should get ECONNRESET.
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));

  cleanup_tcp_test(&s);
}

static void rst_after_fin_test3(void) {
  KTEST_BEGIN("TCP: RST packet after FIN (with blocking read, data available)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.op.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // Send FIN without data.  Should get an ACK.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 505));

  // We should be in CLOSE_WAIT. Send a RST.
  SEND_PKT(&s, RST_PKT(/* seq */ 505, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should get ECONNRESET.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(-ECONNRESET, finish_op(&s));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));  // EOF now.

  cleanup_tcp_test(&s);
}

static void rst_in_lastack_test(void) {
  KTEST_BEGIN("TCP: RST packet in LAST_ACK");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.op.thread);

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
  kthread_enable(s.op.thread);
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, buf, 100));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, buf, 100));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, buf, 100));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, buf, 100));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 3));

  // Poke and prod some other methods while read() is blocked.
  KEXPECT_EQ(-EINVAL, do_bind(s.socket, SRC_IP, 1234));
  KEXPECT_EQ(-EISCONN, do_connect(s.socket, DST_IP, 1234));

  struct sockaddr_in bound_addr;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &bound_addr));
  KEXPECT_EQ(AF_INET, bound_addr.sin_family);
  KEXPECT_STREQ(SRC_IP, ip2str(bound_addr.sin_addr.s_addr));
  KEXPECT_EQ(get_sockaddrs_port((struct sockaddr_storage*)&s.tcp_addr),
             btoh16(bound_addr.sin_port));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 495));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 508, /* wndsize */ 493));
  KEXPECT_EQ(3, finish_op(&s));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  SEND_PKT(&s, DATA_PKT(/* seq */ 508, /* ack */ 101, "hi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 493));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  proc_kill_thread(s.op.thread, SIGUSR1);
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  kthread_disable(s.op.thread);

  proc_kill_thread(s.op.thread, SIGUSR1);
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  // It would also be OK for this to read the data.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_test(void) {
  KTEST_BEGIN("TCP: receive out of order data");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // read() should now block, waiting for data.
  KEXPECT_TRUE(start_read(&s, buf, 20));

  // TODO(aoates): should the window size be updated to account for queued
  // packets?
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_FALSE(ntfn_has_been_notified(&s.op.done));
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_FALSE(ntfn_has_been_notified(&s.op.done));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get one ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 491));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, finish_op(&s));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 9));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_test2(void) {
  KTEST_BEGIN("TCP: receive OOO data (#2, packets in different order)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  // TODO(aoates): should the window size be updated to account for queued
  // packets?
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 491));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, vfs_read(s.socket, buf, 100));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 9));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_test3(void) {
  KTEST_BEGIN("TCP: receive OOO data (#3, newest packet fully replaces queued packets)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  // TODO(aoates): should the window size be updated to account for queued
  // packets?
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "CDE"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "FGH"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcdefgh"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 492));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(8, vfs_read(s.socket, buf, 100));
  buf[8] = '\0';
  KEXPECT_STREQ("abcdefgh", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 8));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_test3b(void) {
  KTEST_BEGIN("TCP: receive OOO data (#3b, newest packet fully replaces queued packets, plus more)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  // TODO(aoates): should the window size be updated to account for queued
  // packets?
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "CDE"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "FGH"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcdefghi"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 491));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, vfs_read(s.socket, buf, 100));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 9));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_test3c(void) {
  KTEST_BEGIN("TCP: receive OOO data (#3c, newest packet fully replaces queued packets [inc. FIN], plus more)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  // TODO(aoates): should the window size be updated to account for queued
  // packets?
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "CDE"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 506, /* ack */ 101, "FGH"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcdefghi"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 491));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, vfs_read(s.socket, buf, 100));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 9));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_multi_hole_test(void) {
  KTEST_BEGIN("TCP: receive OOO data (multiple queued holes)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  // Set it up such that we have multiple holes queued up.  Send the packets in
  // a mixed up order, but we'll end up with:
  // [...][de][fghi][..][lmn][op]
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 512, /* ack */ 101, "lmn"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 515, /* ack */ 101, "op"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the first chunk.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 491));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, vfs_read(s.socket, buf, 100));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  // Now fill in the next holes.
  SEND_PKT(&s, DATA_PKT(/* seq */ 517, /* ack */ 101, "q"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 510));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 510, /* ack */ 101, "jk"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 518));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(8, vfs_read(s.socket, buf, 100));
  buf[8] = '\0';
  KEXPECT_STREQ("jklmnopq", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 17));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_multi_overlap_test(void) {
  KTEST_BEGIN("TCP: receive OOO data (multiple queued overlapping segments)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  // Set up significant overlap in the queued segments.
  // Final string: |abcdefghijklmnopq|
  SEND_PKT(&s, DATA_PKT(/* seq */ 502, /* ack */ 101, "BCdefgh"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 511, /* ack */ 101, "Klmno"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "FGHi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 514, /* ack */ 101, "NOpq"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the first chunk.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 510, /* wndsize */ 491));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, vfs_read(s.socket, buf, 100));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  // Now fill in the next holes.
  SEND_PKT(&s, DATA_PKT(/* seq */ 517, /* ack */ 101, "Q"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 510));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 510, /* ack */ 101, "jk"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 518));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(8, vfs_read(s.socket, buf, 100));
  buf[8] = '\0';
  KEXPECT_STREQ("jklmnopq", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 17));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_fin_test(void) {
  KTEST_BEGIN("TCP: receive OOO data (queued FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 507, /* wndsize */ 495));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(5, vfs_read(s.socket, buf, 100));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_datafin_test(void) {
  KTEST_BEGIN("TCP: receive OOO data (queued DATA+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 506, /* ack */ 101, "fg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 493));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(7, vfs_read(s.socket, buf, 100));
  buf[7] = '\0';
  KEXPECT_STREQ("abcdefg", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 509));
  SEND_PKT(&s, ACK_PKT(/* seq */ 509, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_datafin_overlap_test(void) {
  KTEST_BEGIN("TCP: receive OOO data (queued overlapping DATA+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 506, /* ack */ 101, "fg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  // Send a packet that covers everything BUT the FIN.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcdefg"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 493));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(7, vfs_read(s.socket, buf, 100));
  buf[7] = '\0';
  KEXPECT_STREQ("abcdefg", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 509));
  SEND_PKT(&s, ACK_PKT(/* seq */ 509, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_fin_with_trailing_data_test(void) {
  KTEST_BEGIN("TCP: receive OOO data (queued FIN with data after)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "FGH"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 507, /* wndsize */ 495));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(5, vfs_read(s.socket, buf, 100));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_fin_with_trailing_data_test2(void) {
  KTEST_BEGIN("TCP: receive OOO data (queued FIN with data after #2)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 507, /* ack */ 101, "FGH"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 507, /* wndsize */ 495));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(5, vfs_read(s.socket, buf, 100));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void out_of_order_recv_fin_with_trailing_data_test3(void) {
  KTEST_BEGIN("TCP: receive OOO data (queued FIN with data after #3)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 507, /* ack */ 101, "FGH"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 513, /* ack */ 101, "XYZ"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get an ACK for the whole bunch.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 507, /* wndsize */ 495));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(5, vfs_read(s.socket, buf, 100));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

// Custom test hook that shuts down the socket and reads _some_ of the buffered
// data, on the first call only (the second call will correspond to the packet
// that is causing the reset).
static void ooo_test_shutdown_test_hook(const char* name, int count, void* arg) {
  if (count == 0) {
    KEXPECT_STREQ("ab", do_read_len((intptr_t)arg, 2));
    KEXPECT_EQ(0, net_shutdown((intptr_t)arg, SHUT_RD));
  } else {
    KEXPECT_EQ(-ENOTCONN, net_shutdown((intptr_t)arg, SHUT_RD));
  }
}

static void ooo_close_test_hook(const char* name, int count, void* arg) {
  if (count == 0) {
    KEXPECT_EQ(0, vfs_close((intptr_t)arg));
  }
}

static void out_of_order_recv_shutdown_before_processing_test(void) {
  KTEST_BEGIN("TCP: receive out of order data, but socket is SHUT_RD before processing");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  // Set up a test point to shutdown(SHUT_RD) after the next packet is
  // processed, but before we process the queue.
  test_point_add("tcp:dispatch_packet_action", &ooo_test_shutdown_test_hook,
                 (void*)(intptr_t)s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_EQ(2, test_point_remove("tcp:dispatch_packet_action"));

  // We should get a RST from the first queued packet.  That should correspond
  // to a full reset connection, which will clear the second queued packet and
  // the receive buffer, so we won't get a chance to read the 'c' that was
  // received correctly but still unread.
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_FALSE(raw_has_packets(&s));

  // We should NOT be able to read the "c" from the buffer.
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 100));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_urg_test(void) {
  KTEST_BEGIN("TCP: receive out of order data with URG set");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  SEND_PKT(&s, URG_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // We should get a RST from the first queued packet.  That should correspond
  // to a full reset connection, which will clear the second queued packet and
  // the receive buffer, so we won't get a chance to read the 'abc' that was
  // received correctly.
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_FALSE(raw_has_packets(&s));

  // We should NOT be able to read the "abc" from the buffer.
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 100));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_causes_retransmit_test(void) {
  KTEST_BEGIN("TCP: receive out of order ACKs that [don't] trigger retransmit");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  set_rto(s.socket, 10000);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "123"));

  // Send some packets.
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));

  // Send three dup ACKs.  Should get no retransmits yet because they're still
  // queued (or, more accurately, discarded).
  SEND_PKT(&s, ACK_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));
  SEND_PKT(&s, ACK_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));
  SEND_PKT(&s, ACK_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));

  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  // A retransmit isn't actually triggered, as the ACKs are discarded (rather
  // than queued).  We should just get a plain ACK back.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 510));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(9, vfs_read(s.socket, buf, 100));
  buf[9] = '\0';
  KEXPECT_STREQ("abcdefghi", buf);
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));

  KEXPECT_TRUE(do_standard_finish(&s, 3, 9));
  cleanup_tcp_test(&s);
}

static void out_of_order_recv_close_before_processing_test(void) {
  KTEST_BEGIN("TCP: receive out of order data, close() before handling");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));

  char buf[100];
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));
  vfs_make_nonblock(s.socket);

  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "123"));

  // Send some OOO packets.
  SEND_PKT(&s, DATA_PKT(/* seq */ 503, /* ack */ 101, "Cde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 100));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "fghi"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 104, /* ack */ 501, /* wndsize */ 500));

  test_point_add("tcp:dispatch_packet_action", &ooo_close_test_hook,
                 (void*)(intptr_t)s.socket);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_EQ(2, test_point_remove("tcp:dispatch_packet_action"));

  // Socket should have fully closed due to the reset connection when additional
  // data was received after SHUT_RD.
  s.socket = -1;
  cleanup_tcp_test(&s);
}

static void ooo_queue_tests(void) {
  out_of_order_recv_test();
  out_of_order_recv_test2();
  out_of_order_recv_test3();
  out_of_order_recv_test3b();
  out_of_order_recv_test3c();
  out_of_order_recv_multi_hole_test();
  out_of_order_recv_multi_overlap_test();
  out_of_order_recv_fin_test();
  out_of_order_recv_datafin_test();
  out_of_order_recv_datafin_overlap_test();
  out_of_order_recv_fin_with_trailing_data_test();
  out_of_order_recv_fin_with_trailing_data_test2();
  out_of_order_recv_fin_with_trailing_data_test3();
  out_of_order_recv_shutdown_before_processing_test();
  out_of_order_recv_urg_test();
  out_of_order_recv_causes_retransmit_test();
  out_of_order_recv_close_before_processing_test();
}

static void recv_timeout_test(void) {
  KTEST_BEGIN("TCP: recv() timeout");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 0};
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, 50));
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void recv_timeout_test3(void) {
  KTEST_BEGIN("TCP: recv() timeout (data received)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 50 * 1000};
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 1));
  kthread_disable(s.op.thread);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, 60));

  // Read the data in _this_ thread.
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));

  // Let the other thread wake up.  It should realize that it timed out.
  kthread_enable(s.op.thread);
  KEXPECT_EQ(-ETIMEDOUT, finish_op(&s));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 3));

  cleanup_tcp_test(&s);
}

static void recv_timeout_test4(void) {
  KTEST_BEGIN("TCP: recv() timeout (timeout below ms granularity)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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

static void read_and_shutdown_test(void) {
  KTEST_BEGIN("TCP: shutdown() during blocking read");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  char buf[10];
  KEXPECT_TRUE(start_read(&s, buf, 10));

  async_op_t op2, op3;
  op2.fd = s.socket;
  op3.fd = s.socket;
  KEXPECT_TRUE(start_read_op(&op2, buf, 10));
  KEXPECT_TRUE(start_read_op(&op3, buf, 10));
  kthread_disable(op2.thread);
  kthread_disable(op3.thread);

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

  kthread_enable(op2.thread);
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 102));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));
  KEXPECT_FALSE(ntfn_await_with_timeout(&op2.done, BLOCK_VERIFY_MS));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));
  KEXPECT_EQ(0, finish_op(&s));
  KEXPECT_EQ(0, finish_op_direct(&op2));

  kthread_enable(op3.thread);
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_EQ(0, finish_op_direct(&op3));
  cleanup_tcp_test(&s);
}

static void silly_window_test(void) {
  KTEST_BEGIN("TCP: silly window updates avoided");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 10000));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 9995));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 9990));

  // When some data is read, a small window update should not be sent.
  KEXPECT_STREQ("abcd", do_read_len(s.socket, 4));
  KEXPECT_FALSE(raw_has_packets(&s));

  // When we send more data, the window should not be updated.
  SEND_PKT(&s, DATA_PKT(/* seq */ 511, /* ack */ 101, "1"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 512, /* wndsize */ 9990));
  SEND_PKT(&s, DATA_PKT(/* seq */ 512, /* ack */ 101, "23"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 514, /* wndsize */ 9990));
  SEND_PKT(&s, DATA_PKT(/* seq */ 514, /* ack */ 101, "4"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 515, /* wndsize */ 9990));
  SEND_PKT(&s, DATA_PKT(/* seq */ 515, /* ack */ 101, "5"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 516, /* wndsize */ 9989));
  SEND_PKT(&s, DATA_PKT(/* seq */ 516, /* ack */ 101, "6"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 517, /* wndsize */ 9988));

  // Clear the buf.
  KEXPECT_STREQ("eabcde123456", do_read(s.socket));
  SEND_PKT(&s, DATA_PKT(/* seq */ 517, /* ack */ 101, "ABCD"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 521, /* wndsize */ 9988));
  KEXPECT_STREQ("ABCD", do_read(s.socket));

  // If we update the threshold by an amount larger than the MSS (assumed to be
  // <1500 for this test), then the window should update.
  char* buf = kmalloc(1501);
  kmemset(buf, 'x', 1500);
  buf[1500] = '\0';
  SEND_PKT(&s, DATA_PKT(/* seq */ 521, /* ack */ 101, buf));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 2021, /* wndsize */ 8500));

  KEXPECT_EQ(100, vfs_read(s.socket, buf, 100));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(100, vfs_read(s.socket, buf, 100));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(1300, vfs_read(s.socket, buf, 2000));

  // We should get a window update now.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 2021, /* wndsize */ 10000));

  SEND_PKT(&s, DATA_PKT(/* seq */ 2021, /* ack */ 101, "x"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 2022, /* wndsize */ 9999));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 21 + 1500));

  cleanup_tcp_test(&s);
  kfree(buf);
}

// As above, but test that the algorithm triggers when the buffer size threshold
// is met rather than MSS.
static void silly_window_test2(void) {
  KTEST_BEGIN("TCP: silly window updates avoided (buffer size threshold)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 100));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 95));
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 90));

  // When some data is read, a small window update should not be sent.
  KEXPECT_STREQ("abcd", do_read_len(s.socket, 4));
  KEXPECT_FALSE(raw_has_packets(&s));

  // When we send more data, the window should not be updated.
  char* buf = kmalloc(100);
  kmemset(buf, 'x', 100);
  buf[69] = '\0';

  SEND_PKT(&s, DATA_PKT(/* seq */ 511, /* ack */ 101, buf));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 580, /* wndsize */ 25));

  KEXPECT_EQ(49, vfs_read(s.socket, buf, 49));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Retransmit --- no new window size should be given.
  SEND_PKT(&s, DATA_PKT(/* seq */ 511, /* ack */ 101, buf));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 580, /* wndsize */ 25));

  KEXPECT_EQ(1, vfs_read(s.socket, buf, 1));

  // We should get a window update now.
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 580, /* wndsize */ 75));

  SEND_PKT(&s, DATA_PKT(/* seq */ 511, /* ack */ 101, buf));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 580, /* wndsize */ 75));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 79));

  cleanup_tcp_test(&s);
  kfree(buf);
}

static void no_window_update_in_time_wait(void) {
  KTEST_BEGIN("TCP: no window updates sent when in TIME_WAIT");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 10000));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 9995));

  // Send a large amount of data to induce a window update when we read.
  char* buf = kmalloc(1501);
  kmemset(buf, 'x', 1500);
  buf[1500] = '\0';
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, buf));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 2001, /* wndsize */ 8500));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 2001));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(2001, /* ack */ 102));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_STREQ("FIN_WAIT_2", get_sock_state(s.socket));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 2001, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 2002));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Drain the buffer to attempt to trigger a window update.  We should not get
  // one.
  KEXPECT_EQ(100, vfs_read(s.socket, buf, 100));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(100, vfs_read(s.socket, buf, 100));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(1300, vfs_read(s.socket, buf, 2000));
  KEXPECT_FALSE(raw_has_packets(&s));
  kill_time_wait(s.socket);

  cleanup_tcp_test(&s);
  kfree(buf);
}

static void established_tests(void) {
  basic_established_recv_test();
  rst_during_established_test1();
  rst_during_established_test1b();
  rst_during_established_test1c();
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
  rst_after_fin_test2b();
  rst_after_fin_test3();
  rst_in_lastack_test();
  rst_in_lastack_test2();

  interrupted_recv_test();
  interrupted_recv_test2();

  ooo_queue_tests();

  recv_timeout_test();
  recv_timeout_test2();
  recv_timeout_test3();
  recv_timeout_test4();

  read_and_shutdown_test();

  silly_window_test();
  silly_window_test2();
  no_window_update_in_time_wait();
}

static void recvbuf_size_test(void) {
  KTEST_BEGIN("TCP: SO_RCVBUF");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val;
  socklen_t vallen = sizeof(int);
  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(16 * 1024, val);

  val = 1233;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, sizeof(int)));

  KEXPECT_EQ(0, net_getsockopt(s.socket, SOL_SOCKET, SO_RCVBUF, &val, &vallen));
  KEXPECT_EQ(sizeof(int), vallen);
  KEXPECT_EQ(1233, val);

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
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

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
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, "XXX", 3));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, "XXX", 3));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 108, /* ack */ 502, "5"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 502, /* ack */ 109, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 109, /* wndsize */ 1));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 109, /* ack */ 502));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 109));
  KEXPECT_STREQ("LAST_ACK", get_sock_state(s.socket));
  SEND_PKT(&s, ACK_PKT(/* seq */ 502, /* ack */ 110));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void send_window_wl1_wl2_test(void) {
  KTEST_BEGIN("TCP: send window correctly uses WL1/WL2 test");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // We should be able to send without blocking.  Ack it and close the window.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abc"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ WNDSIZE_ZERO));

  // A segment with new data, even if the ACK is old, should NOT be able to
  // update the window.
  SEND_PKT(&s, DATA_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2, "x"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 104, /* ack */ 502));

  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send new data with a current ACK, which should open the window.
  SEND_PKT(&s, DATA_PKT2(/* seq */ 502, /* ack */ 104, /* wndsize */ 2, "y"));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 503, "12"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 106, /* wndsize */ 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 503, "3"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 107, /* wndsize */ 3));

  // Send more data and partially acknowledge it.
  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 107, /* ack */ 503, "123"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 503, /* ack */ 108, /* wndsize */ WNDSIZE_ZERO));

  // Window is closed.  A segment that doesn't advance WL1 (seq) or WL2 (ack)
  // shouldn't be able to open the window.
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));
  KEXPECT_FALSE(raw_has_packets(&s));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 106, /* wndsize */ 10));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 107, /* wndsize */ 10));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Advancing WL2, even though it doesn't ACK the full data, should update the
  // window.  It should open the window enough for the 2 unacked packets plus
  // one more packet from the latest write.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 109, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 110, /* ack */ 503, "a"));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 109, /* wndsize */ 2));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 503, /* ack */ 109, /* wndsize */ 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 111, /* ack */ 503, "bc"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 503, /* ack */ 113, /* wndsize */ 10));

  // New test when a packet is sent with a previously-seen sequence number; it
  // should not update the window.
  SEND_PKT(&s,
           DATA_PKT2(/* seq */ 503, /* ack */ 113, /* wndsize */ 2, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 113, /* ack */ 506));
  SEND_PKT(&s,
           DATA_PKT2(/* seq */ 504, /* ack */ 113, /* wndsize */ 1, "bcx"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 113, /* ack */ 507));
  SEND_PKT(&s,
           DATA_PKT2(/* seq */ 503, /* ack */ 113, /* wndsize */ 10, "abcxy"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 113, /* ack */ 508));

  KEXPECT_EQ(3, vfs_write(s.socket, "def", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 113, /* ack */ 508, "d"));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 508, /* ack */ 114, /* wndsize */ 10));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 114, /* ack */ 508, "ef"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 508, /* ack */ 116));

  // Test for WL2 handling: need to send a fresh ACK with already-seen data to
  // make sure the window isn't updated then either.
  SEND_PKT(&s,
           DATA_PKT2(/* seq */ 508, /* ack */ 116, /* wndsize */ 2, "123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 116, /* ack */ 511));
  SEND_PKT(&s,
           DATA_PKT2(/* seq */ 509, /* ack */ 116, /* wndsize */ 1, "234"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 116, /* ack */ 512));

  KEXPECT_EQ(3, vfs_write(s.socket, "ghi", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 116, /* ack */ 512, "g"));

  // Sending repeat data with an updated ACK should _not_ update the window.
  SEND_PKT(&s,
           DATA_PKT2(/* seq */ 508, /* ack */ 117, /* wndsize */ 10, "12345"));
  // We should still only get one byte.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 117, /* ack */ 513, "h"));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 513, /* ack */ 118, /* wndsize */ 10));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 118, /* ack */ 513, "i"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 513, /* ack */ 119));


  KEXPECT_TRUE(do_standard_finish(&s, 18, 12));

  cleanup_tcp_test(&s);
}

// As above, but with a socket that comes from a listen socket.
static void send_window_wl1_wl2_incoming_test(void) {
  KTEST_BEGIN(
      "TCP: send window correctly uses WL1/WL2 test (incoming connection)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 2000);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1,
             SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2));
  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);

  // We should be able to send without blocking.  Ack it and close the window.
  KEXPECT_EQ(3, vfs_write(c1.socket, "abc", 3));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 101, /* ack */ 501, "ab"));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 103));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 103, /* ack */ 501, "c"));
  SEND_PKT(&c1,
           ACK_PKT2(/* seq */ 501, /* ack */ 104, /* wndsize */ WNDSIZE_ZERO));

  // A segment with new data, even if the ACK is old, should NOT be able to
  // update the window.
  SEND_PKT(&c1, DATA_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 2, "x"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 104, /* ack */ 502));

  KEXPECT_EQ(3, vfs_write(c1.socket, "123", 3));
  KEXPECT_FALSE(raw_has_packets(&c1));

  // Send new data with a current ACK, which should open the window.
  SEND_PKT(&c1, DATA_PKT2(/* seq */ 502, /* ack */ 104, /* wndsize */ 2, "y"));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 104, /* ack */ 503, "12"));
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 106, /* wndsize */ 3));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 106, /* ack */ 503, "3"));
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 107, /* wndsize */ 3));

  // Send more data and partially acknowledge it.
  KEXPECT_EQ(3, vfs_write(c1.socket, "123", 3));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 107, /* ack */ 503, "123"));
  SEND_PKT(&c1,
           ACK_PKT2(/* seq */ 503, /* ack */ 108, /* wndsize */ WNDSIZE_ZERO));

  // Window is closed.  A segment that doesn't advance WL1 (seq) or WL2 (ack)
  // shouldn't be able to open the window.
  KEXPECT_EQ(3, vfs_write(c1.socket, "abc", 3));
  KEXPECT_FALSE(raw_has_packets(&c1));
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 106, /* wndsize */ 10));
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 107, /* wndsize */ 10));
  KEXPECT_FALSE(raw_has_packets(&c1));

  // Advancing WL2, even though it doesn't ACK the full data, should update the
  // window.  It should open the window enough for the 2 unacked packets plus
  // one more packet from the latest write.
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 109, /* wndsize */ 2));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 110, /* ack */ 503, "a"));

  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 109, /* wndsize */ 2));
  KEXPECT_FALSE(raw_has_packets(&c1));

  SEND_PKT(&c1, ACK_PKT2(/* seq */ 503, /* ack */ 109, /* wndsize */ 5));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 111, /* ack */ 503, "bc"));
  SEND_PKT(&c1,
           ACK_PKT2(/* seq */ 503, /* ack */ 113, /* wndsize */ 10));

  // New test when a packet is sent with a previously-seen sequence number; it
  // should not update the window.
  SEND_PKT(&c1,
           DATA_PKT2(/* seq */ 503, /* ack */ 113, /* wndsize */ 2, "abc"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 113, /* ack */ 506));
  SEND_PKT(&c1,
           DATA_PKT2(/* seq */ 504, /* ack */ 113, /* wndsize */ 1, "bcx"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 113, /* ack */ 507));
  SEND_PKT(&c1,
           DATA_PKT2(/* seq */ 503, /* ack */ 113, /* wndsize */ 10, "abcxy"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 113, /* ack */ 508));

  KEXPECT_EQ(3, vfs_write(c1.socket, "def", 3));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 113, /* ack */ 508, "d"));

  SEND_PKT(&c1, ACK_PKT2(/* seq */ 508, /* ack */ 114, /* wndsize */ 10));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 114, /* ack */ 508, "ef"));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 508, /* ack */ 116));

  // Test for WL2 handling: need to send a fresh ACK with already-seen data to
  // make sure the window isn't updated then either.
  SEND_PKT(&c1,
           DATA_PKT2(/* seq */ 508, /* ack */ 116, /* wndsize */ 2, "123"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 116, /* ack */ 511));
  SEND_PKT(&c1,
           DATA_PKT2(/* seq */ 509, /* ack */ 116, /* wndsize */ 1, "234"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 116, /* ack */ 512));

  KEXPECT_EQ(3, vfs_write(c1.socket, "ghi", 3));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 116, /* ack */ 512, "g"));

  // Sending repeat data with an updated ACK should _not_ update the window.
  SEND_PKT(&c1,
           DATA_PKT2(/* seq */ 508, /* ack */ 117, /* wndsize */ 10, "12345"));
  // We should still only get one byte.
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 117, /* ack */ 513, "h"));
  SEND_PKT(&c1, ACK_PKT2(/* seq */ 513, /* ack */ 118, /* wndsize */ 10));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 118, /* ack */ 513, "i"));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 513, /* ack */ 119));

  KEXPECT_TRUE(do_standard_finish(&c1, 18, 12));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void basic_send_test_blocks(void) {
  KTEST_BEGIN("TCP: basic data passing (blocking send)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  KEXPECT_TRUE(start_write(&s, "fgh"));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  // Finally send an ACK.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(do_standard_finish(&s, 5, 0));

  cleanup_tcp_test(&s);
}

static void send_blocking_shutdown(void) {
  KTEST_BEGIN("TCP: blocking send interrupted with shutdown");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  KEXPECT_TRUE(start_write(&s, "fgh"));

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));

  ksigset_t signew, sigold;
  ksigemptyset(&signew);
  ksigaddset(&signew, SIGPIPE);
  KEXPECT_EQ(0, proc_sigprocmask(SIG_BLOCK, &signew, &sigold));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 106, /* ack */ 501));
  KEXPECT_EQ(-EPIPE, finish_op(&s));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KEXPECT_EQ(0, proc_sigprocmask(SIG_SETMASK, &sigold, NULL));

  // Finally send an ACK.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  cleanup_tcp_test(&s);
}

static void send_timeout_test(void) {
  KTEST_BEGIN("TCP: send() timeout");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_timeval tv = {0, 50 * 1000};
  KEXPECT_EQ(0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDTIMEO, &tv,
                                     sizeof(tv)));

  // Fill the buffer, then get a thread blocking.
  KEXPECT_EQ(5, vfs_write(s.socket, "abcdef", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "abcde"));
  KEXPECT_TRUE(start_write(&s, "fgh"));
  kthread_disable(s.op.thread);
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));
  KEXPECT_FALSE(raw_has_packets_wait(&s, 60));

  // Fill the buffer up again from another thread.
  KEXPECT_EQ(5, vfs_write(s.socket, "123456", 6));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "12345"));

  kthread_enable(s.op.thread);
  KEXPECT_EQ(-ETIMEDOUT, finish_op(&s));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(do_standard_finish(&s, 10, 0));

  cleanup_tcp_test(&s);
}

static void send_error_test(void) {
  KTEST_BEGIN("TCP: send() has socket error");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 108, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 108, /* ack */ 502, "h"));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 110));

  cleanup_tcp_test(&s);
}

static void shutdown_with_data_buffered_pending_send(void) {
  KTEST_BEGIN("TCP: shutdown() with buffered data (blocking send)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  s.wndsize = 3;

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 108, /* wndsize */ 2));
  EXPECT_PKT(&s, DATA_FIN_PKT(/* seq */ 108, /* ack */ 502, "h"));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 110));

  cleanup_tcp_test(&s);
}

static void shutdown_with_zero_window(void) {
  KTEST_BEGIN("TCP: shutdown() doesn't send FIN with zero window");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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

  // Should NOT get a FIN because the window is zero.
  KEXPECT_FALSE(raw_has_packets(&s));

  // Should get the FIN once we open the window.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 104, /* wndsize */ 1));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 105));

  cleanup_tcp_test(&s);
}

static void shutdown_with_zero_recv_window(void) {
  KTEST_BEGIN("TCP: shutdown() rejects FIN with zero recv window");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 5));

  // When the full packet is too long, we should drop the FIN.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 506, /* ack */ 101, "12345"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("12345", do_read(s.socket));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 504));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 504, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 504));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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

static void send_tests(void) {
  basic_send_test();
  basic_send_window_test();
  basic_send_window_test2();
  send_window_wl1_wl2_test();
  send_window_wl1_wl2_incoming_test();
  basic_send_test_blocks();
  basic_send_test_blocks2();
  send_blocking_interrupted();
  send_blocking_shutdown();
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 5));


  // Test #2: as above, but is exactly aligned with start of window (still too
  // long).  This should be trimmed.
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 2));
  SEND_PKT(&s, DATA_PKT(/* seq */ 509, /* ack */ 101, "4567"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("12345", do_read(s.socket));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));

  // Test #3: extends past window and doesn't align with start of window.
  // Should be dropped.
  SEND_PKT(&s, DATA_PKT(/* seq */ 512, /* ack */ 101, "567890abcdefg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
  KEXPECT_FALSE(socket_has_data(s.socket, 0));

  // Test #4: doesn't align wih start of window, but is within window.  Should
  // be dropped.
  SEND_PKT(&s, DATA_PKT(/* seq */ 512, /* ack */ 101, "X"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
  KEXPECT_FALSE(socket_has_data(s.socket, 0));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 10));

  cleanup_tcp_test(&s);
}

// Basically exactly the same as above, but with FINs past end-of-window.
static void data_fin_past_window_test(void) {
  KTEST_BEGIN("TCP: data packet extends past window (with FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 506, /* wndsize */ 5));


  // Test #2: as above, but is exactly aligned with start of window (still too
  // long).  This should be trimmed (and FIN ignored).
  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 509, /* wndsize */ 2));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 509, /* ack */ 101, "4567"));
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_STREQ("12345", do_read(s.socket));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));

  // Test #3: extends past window and doesn't align with start of window.
  // Should be dropped.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 512, /* ack */ 101, "567890abcdefg"));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 511, /* wndsize */ 5));
  KEXPECT_FALSE(socket_has_data(s.socket, 0));

  // Test a correct in-window FIN with data that starts before the window.
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 509, /* ack */ 101, "456789"));

  // Should get an ACK.
  EXPECT_PKT(
      &s, ACK_PKT2(/* seq */ 101, /* ack */ 516, /* wndsize */ 1));
  KEXPECT_STREQ("6789", do_read(s.socket));
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 516, /* wndsize */ 5));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  EXPECT_PKT(&s, ACK_PKT2(/* seq */ 101, /* ack */ 505, /* wndsize */ 5));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 6));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 5));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
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
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));

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
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));

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
  KEXPECT_EQ(0, do_setsockopt_int(sock2, SOL_SOCKET, SO_REUSEADDR, 1));
  KEXPECT_EQ(0, do_bind(sock2, SRC_IP, 0x1234));
  KEXPECT_EQ(-EADDRINUSE, do_connect(sock2, DST_IP, 0x5678));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  int val = 0;
  socklen_t vallen = sizeof(int);
  KEXPECT_EQ(0, net_getsockopt(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN,
                               &val, &vallen));
  KEXPECT_EQ(40, val);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  // ...but a RST should get nothing.
  SEND_PKT(&s, RST_PKT(/* seq */ 50, /* ack */ 20));
  SEND_PKT(&s, RST_NOACK_PKT(/* seq */ 50));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void active_close1b(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT); "
      "retransmitted FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

// Exact same as above, but with the retransmitted FIN coming with data (also
// retransmitted).
static void active_close1c(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT); "
      "retransmitted FIN (with data)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 60));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close1d(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT); "
      "TIME_WAIT gets FIN with misaligned sequence number");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 50));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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

  KEXPECT_EQ(0, get_so_error(s.socket));

  cleanup_tcp_test(&s);
}

static void active_close3(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT, with "
      "data+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ 3));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_shutrd_data2(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_1, with data "
              "but doesn't ACK the FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_shutrd_datafin(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_1, with DATA_FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw2_rst(void) {
  KTEST_BEGIN("TCP: active close (RST in FIN_WAIT_2)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw2_shutrd_data2(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_2, with data "
              "but doesn't ACK the FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw2_shutrd_datafin(void) {
  KTEST_BEGIN("TCP: active close (shutdown(RD) in FIN_WAIT_2, with DATA_FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_to_tw(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> TIME_WAIT)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw1_to_tw_datafin(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> TIME_WAIT with data+FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing1(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing1b(void) {
  KTEST_BEGIN("TCP: active close (FIN_WAIT_1 -> CLOSING -> TIME_WAIT), "
              "ACK in the past");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(
      0, do_setsockopt_int(s.socket, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 40));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 20));

  cleanup_tcp_test(&s);
}

static void active_close_fw_to_closing_rst(void) {
  KTEST_BEGIN(
      "TCP: active close (FIN_WAIT_1 -> CLOSING -> RST)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 105, /* wndsize */ 3));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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

  SEND_PKT(&s, ACK_PKT2(/* seq */ 502, /* ack */ 105, /* wndsize */ 3));
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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  s.socket = -1;
  cleanup_tcp_test(&s);
}

static void close_shutdown_test3(void) {
  KTEST_BEGIN("TCP: close() connecting socket");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  // TODO(aoates): figure out how to signal that the FD is closed to the other
  // thread, and have connect() return ECONNABORTED.
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  s.socket = -1;
  cleanup_tcp_test(&s);
}

// As above, but kill the connect() call before calling close().
static void close_shutdown_test3b(void) {
  KTEST_BEGIN("TCP: close() connecting socket #2");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_FALSE(raw_has_packets(&s));

  s.socket = -1;
  cleanup_tcp_test(&s);
}

static void close_shutdown_test4(void) {
  KTEST_BEGIN("TCP: close() connected socket");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

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
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do simultaneous connect.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  // Force the connect() to finish.
  proc_kill_thread(s.op.thread, SIGUSR1);
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

static void close_shutdown_test6(void) {
  KTEST_BEGIN("TCP: close() socket after shutdown(SHUT_RD)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));

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

static void close_shutdown_test7(void) {
  KTEST_BEGIN("TCP: close() socket after shutdown(SHUT_WR)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  // Continue the shutdown after the fd is closed.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void close_shutdown_test7b(void) {
  KTEST_BEGIN("TCP: close() socket after shutdown(SHUT_WR) [send data]");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  // The socket should have done the equivalent of SHUT_RD, so sending data
  // should trigger a RST.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));

  cleanup_tcp_test(&s);
}

static void close_shutdown_test8(void) {
  KTEST_BEGIN("TCP: close() socket after shutdown(SHUT_RDWR)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  // Continue the shutdown after the fd is closed.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void close_shutdown_test8b(void) {
  KTEST_BEGIN("TCP: close() socket after shutdown(SHUT_RDWR) [send data]");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_STREQ("FIN_WAIT_1", get_sock_state(s.socket));

  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  // The socket should have done the equivalent of SHUT_RD, so sending data
  // should trigger a RST.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 102, "abc"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 102, /* ack */ 501));

  cleanup_tcp_test(&s);
}

static void close_shutdown_test(void) {
  close_shutdown_test1();
  close_shutdown_test2();
  close_shutdown_test3();
  close_shutdown_test3b();
  close_shutdown_test4();
  close_shutdown_test5();
  close_shutdown_test6();
  close_shutdown_test7();
  close_shutdown_test7b();
  close_shutdown_test8();
  close_shutdown_test8b();
}

static void basic_listen_test(void) {
  KTEST_BEGIN("TCP: listen() basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  // Sholud not be able to listen on an unbound socket.
  KEXPECT_EQ(-EDESTADDRREQ, net_listen(s.socket, 10));

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_EQ(0, net_listen(s.socket, 10));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_EQ(-EINVAL, net_listen(s.socket, 10));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));

  // Should not be able to call connect() on a listening socket.
  KEXPECT_EQ(-EOPNOTSUPP, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // Or read/write.
  char buf;
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, &buf, 1));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, &buf, 1));

  struct sockaddr_in sin;
  KEXPECT_EQ(0, getsockname_inet(s.socket, &sin));
  KEXPECT_STREQ(SRC_IP ":4660", sin2str(&sin));
  KEXPECT_EQ(-ENOTCONN, getpeername_inet(s.socket, &sin));

  // Any packet other than a SYN should get a RST or be ignored.
  SEND_PKT(&s, RST_PKT(/* seq */ 500, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 5000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, DATA_PKT(/* seq */ 500, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 500, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, FIN_PKT(/* seq */ 500, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  // Try some mutants that don't have the ACK bit set for fun.
  SEND_PKT(&s, NOACK(DATA_PKT(/* seq */ 500, /* ack */ 101, "abc")));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 503));
  SEND_PKT(&s, NOACK(DATA_FIN_PKT(/* seq */ 500, /* ack */ 101, "abc")));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 504));
  SEND_PKT(&s, NOACK(FIN_PKT(/* seq */ 500, /* ack */ 101)));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 501));

  // A SYN (or SYN-ACK) with data should also be rejected.
  test_packet_spec_t p = DATA_PKT(/* seq */ 500, /* ack */ 101, "abc");
  p.flags = TCP_FLAG_SYN;
  SEND_PKT(&s, p);
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 504));
  p.flags |= TCP_FLAG_ACK;
  SEND_PKT(&s, p);
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  // Send a SYN, complete the connection.
  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 2000);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1,
             SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));

  // We should be able to accept() a child socket.
  char addr[SOCKADDR_PRETTY_LEN];
  c1.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ(DST_IP ":2000", addr);
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // listen(), accept(), etc should not work on the child socket.
  KEXPECT_EQ(-EINVAL, net_listen(c1.socket, 10));
  KEXPECT_EQ(-EINVAL, do_accept(c1.socket, addr));
  KEXPECT_EQ(-EINVAL, net_accept_queue_length(c1.socket));

  // Do a second connection.
  tcp_test_state_t c2;
  init_tcp_test_child(&s, &c2, DST_IP_2, 600);
  SEND_PKT(&c2, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c2,
             SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  SEND_PKT(&c2, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  c2.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c2.socket, 0);
  KEXPECT_STREQ(DST_IP_2 ":600", addr);
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // Should be able to pass data on both sockets.
  SEND_PKT(&c1, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  SEND_PKT(&c2, DATA_PKT(/* seq */ 501, /* ack */ 101, "123"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 504));
  EXPECT_PKT(&c2, ACK_PKT(/* seq */ 101, /* ack */ 504));

  KEXPECT_STREQ("abc", do_read(c1.socket));
  KEXPECT_STREQ("123", do_read(c2.socket));

  KEXPECT_EQ(5, vfs_write(c1.socket, "ABCDE", 5));
  KEXPECT_EQ(5, vfs_write(c2.socket, "67890", 5));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 101, /* ack */ 504, "ABCDE"));
  EXPECT_PKT(&c2, DATA_PKT(/* seq */ 101, /* ack */ 504, "67890"));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 504, /* ack */ 106));
  SEND_PKT(&c2, ACK_PKT(/* seq */ 504, /* ack */ 106));

  KEXPECT_TRUE(do_standard_finish(&c1, 5, 3));
  KEXPECT_TRUE(do_standard_finish(&c2, 5, 3));

  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(c1.socket));
  KEXPECT_EQ(-EINVAL, net_listen(c1.socket, 10));

  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&c2);
}

static void listen_queue_max_test(void) {
  KTEST_BEGIN("TCP: listen() hits max queue length test");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  // Attempt to open four connections.
  tcp_test_state_t c1, c2, c3, c4, c5;
  init_tcp_test_child(&s, &c1, DST_IP_PREFIX ".2", 1002);
  init_tcp_test_child(&s, &c2, DST_IP_PREFIX ".3", 1003);
  init_tcp_test_child(&s, &c3, DST_IP_PREFIX ".4", 1004);
  init_tcp_test_child(&s, &c4, DST_IP_PREFIX ".5", 1005);
  init_tcp_test_child(&s, &c5, DST_IP_PREFIX ".6", 1006);

  // The first three should succeed.  Leave one in SYN_RCVD.
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 16384));
  // No ACK (yet).

  SEND_PKT(&c2, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c2, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 16384));
  SEND_PKT(&c2, ACK_PKT(/* seq */ 501, /* ack */ 101));

  SEND_PKT(&c3, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c3, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 16384));
  SEND_PKT(&c3, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(3, net_accept_queue_length(s.socket));

  // The fourth should be rejected.
  SEND_PKT(&c4, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c4, RST_PKT(/* seq */ 0, /* ack */ 501));
  SEND_PKT(&c4, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c4, RST_PKT(/* seq */ 0, /* ack */ 501));
  KEXPECT_EQ(3, net_accept_queue_length(s.socket));

  // Note: technically it's not guaranteed sockets will be given in FIFO order.
  char addr[SOCKADDR_PRETTY_LEN];
  c2.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c2.socket, 0);
  KEXPECT_STREQ(DST_IP_PREFIX ".3:1003", addr);
  KEXPECT_EQ(2, net_accept_queue_length(s.socket));

  // Now the fourth should be able to connect.
  SEND_PKT(&c4, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c4, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 16384));
  SEND_PKT(&c4, ACK_PKT(/* seq */ 501, /* ack */ 101));

  // ...a fifth should be rejected.
  SEND_PKT(&c5, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c5, RST_PKT(/* seq */ 0, /* ack */ 501));

  // When we close the listening socket, any queued sockets should be reset.
  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;

  EXPECT_PKT(&c1, RST_PKT(/* seq */ 101, /* ack */ 501));
  EXPECT_PKT(&c3, RST_PKT(/* seq */ 101, /* ack */ 501));
  EXPECT_PKT(&c4, RST_PKT(/* seq */ 101, /* ack */ 501));

  // c2 should still be usable.
  SEND_PKT(&c2, DATA_PKT(/* seq */ 501, /* ack */ 101, "123"));
  EXPECT_PKT(&c2, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_STREQ("123", do_read(c2.socket));

  do_standard_finish(&c2, 0, 3);

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&c2);
  cleanup_tcp_test(&c3);
  cleanup_tcp_test(&c4);
  cleanup_tcp_test(&c5);
}

static void do_backlog_test(tcp_test_state_t* s, int backlog) {
  tcp_test_state_t* c = kmalloc(sizeof(tcp_test_state_t) * (backlog + 1));
  char addr[SOCKADDR_PRETTY_LEN];
  for (int i = 0; i < backlog + 1; ++i) {
    ksprintf(addr, "%s.%d", DST_IP_PREFIX, i + 2);
    init_tcp_test_child(s, &c[i], addr, 1000);
  }

  for (int i = 0; i < backlog; ++i) {
    SEND_PKT(&c[i], SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
    EXPECT_PKT(&c[i], SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
    SEND_PKT(&c[i], ACK_PKT(/* seq */ 501, /* ack */ 101));
  }

  SEND_PKT(&c[backlog], SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c[backlog], RST_PKT(/* seq */ 0, /* ack */ 501));

  for (int i = 0; i < backlog + 1; ++i) {
    cleanup_tcp_test(&c[i]);
  }
  kfree(c);
}

static void listen_backlog_values_test(void) {
  KTEST_BEGIN("TCP: listen() backlog negative");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, -1));
  do_backlog_test(&s, 10);
  cleanup_tcp_test(&s);


  KTEST_BEGIN("TCP: listen() backlog zero");
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 0));
  do_backlog_test(&s, 10);
  cleanup_tcp_test(&s);


  KTEST_BEGIN("TCP: listen() backlog huge");
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, INT_MAX));
  // Don't bother checking that it's actually clamped, but make sure at least
  // one connection works.
  tcp_test_state_t c1;
  do_child_connect(&s, &c1, DST_IP, 1002, 500);
  do_standard_finish(&c1, 0, 0);
  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_blocks_test(void) {
  KTEST_BEGIN("TCP: accept() blocks until socket available");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  KEXPECT_TRUE(start_accept(&s));

  tcp_test_state_t c1, c2, c3;
  init_tcp_test_child(&s, &c1, DST_IP_PREFIX ".2", 1002);
  init_tcp_test_child(&s, &c2, DST_IP_PREFIX ".3", 1002);
  init_tcp_test_child(&s, &c3, DST_IP_PREFIX ".4", 1002);

  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c2, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c2, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c3, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c3, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));

  // accept() shouldn't return yet.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

  kthread_disable(s.op.thread);
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  // Thread should be woken up but not run.
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

  // Accept the socket in this thread.
  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);

  kthread_enable(s.op.thread);
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

  // Another connection should wake it up.
  SEND_PKT(&c2, ACK_PKT(/* seq */ 501, /* ack */ 101));
  SEND_PKT(&c3, ACK_PKT(/* seq */ 501, /* ack */ 101));
  c2.socket = finish_op(&s);
  KEXPECT_GE(c2.socket, 0);

  do_standard_finish(&c1, 0, 0);
  do_standard_finish(&c2, 0, 0);

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&c2);
  cleanup_tcp_test(&c3);
}

static void accept_blocks_test2(void) {
  KTEST_BEGIN("TCP: accept() interrupted by signal");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  KEXPECT_TRUE(start_accept(&s));
  proc_kill_thread(s.op.thread, SIGUSR1);

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);

  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));

  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));

  // accept() should indicate a signal.
  KEXPECT_EQ(-EINTR, finish_op(&s));

  // Socket should still be acceptable here.
  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));

  do_standard_finish(&c1, 0, 0);

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_blocks_test3(void) {
  KTEST_BEGIN("TCP: accept() blocks when socket is already in SYN_RCVD");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));

  // accept() shouldn't return yet.
  KEXPECT_TRUE(start_accept(&s));

  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  c1.socket = finish_op(&s);
  KEXPECT_GE(c1.socket, 0);

  do_standard_finish(&c1, 0, 0);

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void listen_on_any_addr_test(void) {
  KTEST_BEGIN("TCP: listen()/accept() on a socket bound to ANY-addr");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, "0.0.0.0", 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);

  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));

  // Accept the socket in this thread.
  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);

  SEND_PKT(&c1, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_STREQ("abc", do_read(c1.socket));

  KEXPECT_EQ(2, vfs_write(c1.socket, "de", 2));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 101, /* ack */ 504, "de"));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 504, /* ack */ 103));

  KEXPECT_TRUE(do_standard_finish(&c1, 2, 3));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_address_params_test(void) {
  KTEST_BEGIN("TCP: accept() validates params (NULL address)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  struct sockaddr_storage addr, zero_addr;
  kmemset(&addr, 0, sizeof(addr));
  kmemset(&zero_addr, 0, sizeof(zero_addr));
  socklen_t len;
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  len = 1234;
  int child = net_accept(s.socket, NULL, &len);
  KEXPECT_GE(child, 0);
  KEXPECT_EQ(1234, len);
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, vfs_close(child));

  KTEST_BEGIN("TCP: accept() validates params (NULL address_len)");
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  child = net_accept(s.socket, (struct sockaddr*)&addr, NULL);
  KEXPECT_GE(child, 0);
  KEXPECT_EQ(0, kmemcmp(&addr, &zero_addr, sizeof(addr)));
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, vfs_close(child));

  // The both NULL case is already tested above.

  KTEST_BEGIN("TCP: accept() validates params (negative address_len)");
  len = -5;
  KEXPECT_EQ(-EINVAL, net_accept(s.socket, (struct sockaddr*)&addr, &len));
  KEXPECT_EQ(-5, len);
  KEXPECT_EQ(0, kmemcmp(&addr, &zero_addr, sizeof(addr)));

  KTEST_BEGIN("TCP: accept() validates params (zero address_len)");
  len = 0;
  KEXPECT_EQ(-EINVAL, net_accept(s.socket, (struct sockaddr*)&addr, &len));
  KEXPECT_EQ(0, len);
  KEXPECT_EQ(0, kmemcmp(&addr, &zero_addr, sizeof(addr)));

  KTEST_BEGIN("TCP: accept() validates params (too-small address_len)");
  len = 7;
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  kmemset(&addr, 0, sizeof(addr));
  child = net_accept(s.socket, (struct sockaddr*)&addr, &len);
  KEXPECT_GE(child, 0);
  KEXPECT_EQ(7, len);
  KEXPECT_EQ(AF_INET, addr.sa_family);
  // Shouldn't have written past byte 7.
  kmemset(&addr, 0, 7);
  KEXPECT_EQ(0, kmemcmp(&addr, &zero_addr, sizeof(addr)));
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, vfs_close(child));

  KTEST_BEGIN("TCP: accept() validates params (too-large address_len)");
  char bigbuf[sizeof(struct sockaddr_storage) * 2];
  kmemset(bigbuf, 0, sizeof(struct sockaddr_storage) * 2);
  len = sizeof(struct sockaddr_storage) * 2;
  bigbuf[sizeof(struct sockaddr_storage)] = 0xab;
  bigbuf[sizeof(struct sockaddr_storage) + 1] = 0xdf;
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  child = net_accept(s.socket, (struct sockaddr*)bigbuf, &len);
  KEXPECT_GE(child, 0);
  // We should have written the sockaddr_in fields correctly.
  KEXPECT_EQ(sizeof(struct sockaddr_in), len);
  // The first part of the address (struct sockaddr_in) should match.
  KEXPECT_EQ(AF_INET, ((struct sockaddr_in*)&bigbuf)->sin_family);
  KEXPECT_EQ(str2inet(DST_IP), ((struct sockaddr_in*)&bigbuf)->sin_addr.s_addr);
  KEXPECT_EQ(btoh16(1002), ((struct sockaddr_in*)&bigbuf)->sin_port);
  // Shouldn't have written past the last byte.
  KEXPECT_EQ((uint8_t)0xab, bigbuf[sizeof(struct sockaddr_storage)]);
  KEXPECT_EQ((uint8_t)0xdf, bigbuf[sizeof(struct sockaddr_storage) + 1]);
  // ...everything in between is gargbage, can't be checked.
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, vfs_close(child));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_child_rst1(void) {
  KTEST_BEGIN("TCP: blocking accept() with socket RST in SYN_RCVD");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 1));

  KEXPECT_TRUE(start_accept(&s));
  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));


  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&c1, RST_NOACK_PKT(/* seq */ 101));
  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));

  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));

  c1.socket = finish_op(&s);
  KEXPECT_GE(c1.socket, 0);

  do_standard_finish(&c1, 0, 0);

  // Make sure that nothing funny happens on close after a reset pending child.
  KEXPECT_EQ(0, vfs_close(s.socket));
  s.socket = -1;
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_child_rst2(void) {
  KTEST_BEGIN("TCP: accept() gets socket that was already reset");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));

  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);
  addr.sa_family = 123;
  int child = net_accept(s.socket, (struct sockaddr*)&addr, &len);
  KEXPECT_GE(child, 0);
  // Currently if the connection is closed, we don't retain the peer address.
  KEXPECT_EQ(AF_UNSPEC, addr.sa_family);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(child));
  char buf;
  KEXPECT_EQ(-ECONNRESET, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_close(child));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_child_rst3(void) {
  KTEST_BEGIN("TCP: blocking accept() gets socket that was already reset");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  KEXPECT_TRUE(start_accept(&s));
  kthread_disable(s.op.thread);

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));

  kthread_enable(s.op.thread);
  int child = finish_op(&s);
  KEXPECT_GE(child, 0);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(child));
  char buf;
  KEXPECT_EQ(-ECONNRESET, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_close(child));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_child_rst4(void) {
  KTEST_BEGIN("TCP: accept() gets socket that was already reset (w/ data)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 505));
  SEND_PKT(&c1, RST_PKT(/* seq */ 505, /* ack */ 101));

  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);
  addr.sa_family = 123;
  int child = net_accept(s.socket, (struct sockaddr*)&addr, &len);
  KEXPECT_GE(child, 0);
  // Currently if the connection is closed, we don't retain the peer address.
  KEXPECT_EQ(AF_UNSPEC, addr.sa_family);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(child));
  char buf;
  KEXPECT_EQ(-ECONNRESET, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_close(child));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void send_test_rst(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, RST_PKT(/* seq */ 501, /* ack */ 101));
}

static void accept_child_rst5(void) {
  KTEST_BEGIN("TCP: close() listening socket race with RST (SYN_RCVD)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 1));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));

  // Trigger the race condition.
  test_point_add("tcp:close_listening", &send_test_rst, &c1);
  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_EQ(1, test_point_remove("tcp:close_listening"));
  s.socket = -1;
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_child_partial_close(void) {
  KTEST_BEGIN("TCP: accept() gets socket that was partially closed");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, DATA_FIN_PKT(/* seq */ 501, /* ack */ 101, "abc"));

  char addr[SOCKADDR_PRETTY_LEN];
  int child = do_accept(s.socket, addr);
  KEXPECT_GE(child, 0);
  KEXPECT_STREQ(DST_IP ":1002", addr);
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(child));
  KEXPECT_STREQ("abc", do_read(child));
  char buf;
  KEXPECT_EQ(0, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_close(child));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void accept_child_partial_close2(void) {
  KTEST_BEGIN("TCP: accept() gets socket that was partially closed #2");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 3));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  SEND_PKT(&c1, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 504));
  SEND_PKT(&c1, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 505));

  char addr[SOCKADDR_PRETTY_LEN];
  int child = do_accept(s.socket, addr);
  KEXPECT_GE(child, 0);
  KEXPECT_STREQ(DST_IP ":1002", addr);
  KEXPECT_STREQ("CLOSE_WAIT", get_sock_state(child));
  KEXPECT_STREQ("abc", do_read(child));
  char buf;
  KEXPECT_EQ(0, vfs_read(child, &buf, 1));
  KEXPECT_EQ(0, vfs_close(child));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 505, /* ack */ 102));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void send_test_syn(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(s, RST_PKT(/* seq */ 0, /* ack */ 501));
}

static void syn_during_listen_close_test(void) {
  KTEST_BEGIN("TCP: close() listening socket race with new SYN");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 1));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);

  // Trigger the race condition.  Do it directly by unreffing the file_t to
  // avoid problems locking the process mutex in vfs_close.
  file_t* socket_file = NULL;
  KEXPECT_EQ(0, lookup_fd(s.socket, &socket_file));  // Get a ref.
  KEXPECT_EQ(0, vfs_close(s.socket));  // Close the FD.

  test_point_add("tcp:close_listening", &send_test_syn, &c1);
  file_unref(socket_file);  // Release the last reference.
  KEXPECT_EQ(1, test_point_remove("tcp:close_listening"));
  s.socket = -1;
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void send_test_ack(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, ACK_PKT(/* seq */ 501, /* ack */ 101));
}

static void syn_during_listen_close_test2(void) {
  KTEST_BEGIN("TCP: close() listening socket race with ACK "
              "(SYN_RCVD -> ESTABLISHED)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 1));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));

  // Trigger the race condition.
  test_point_add("tcp:close_listening", &send_test_ack, &c1);
  KEXPECT_EQ(0, vfs_close(s.socket));
  KEXPECT_EQ(1, test_point_remove("tcp:close_listening"));
  s.socket = -1;
  EXPECT_PKT(&c1, RST_PKT(/* seq */ 101, /* ack */ 501));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

typedef struct {
  notification_t hook_hit;
  notification_t hook_done;
  tcp_test_state_t* s;
  tcp_test_state_t* c1;
} simulcnt_args_t;

static void simultaneous_connect_test_point(const char* name, int count,
                                            void* arg) {
  simulcnt_args_t* args = (simulcnt_args_t*)arg;
  // Avoid the recursive case --- only pause the first time we dispatch.
  if (ntfn_has_been_notified(&args->hook_hit)) {
    return;
  }
  ntfn_notify(&args->hook_hit);
  KEXPECT_TRUE(ntfn_await_with_timeout(&args->hook_done, 2000));
}

static void* simultaneous_connect_thread(void* arg) {
  simulcnt_args_t* args = (simulcnt_args_t*)arg;
  // Wait until the main thread has started to dispatch the first SYN.
  KEXPECT_TRUE(ntfn_await_with_timeout(&args->hook_hit, 2000));

  // Inject a new SYN and create the connection first!  Ha!
  SEND_PKT(args->c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(args->c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(args->c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(1, net_accept_queue_length(args->s->socket));
  ntfn_notify(&args->hook_done);
  return NULL;
}

static void simultaneous_connections_same_5tuple(void) {
  KTEST_BEGIN("TCP: two SYNs from same 5-tuple race");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1002);

  simulcnt_args_t args;
  ntfn_init(&args.hook_hit);
  ntfn_init(&args.hook_done);
  args.s = &s;
  args.c1 = &c1;

  kthread_t thread;
  KEXPECT_EQ(0,
             proc_thread_create(&thread, &simultaneous_connect_thread, &args));

  // Send a SYN, which will trigger the other thread to send a SYN as well and
  // beat us to it.
  test_point_add("tcp:dispatch_packet", &simultaneous_connect_test_point,
                 &args);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 600, /* wndsize */ 8000));
  // In this race, we simply ignore the second SYN (rather than sending a
  // challenge ACK, which technically is what we should do).
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(3, test_point_remove("tcp:dispatch_packet"));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  KEXPECT_EQ(NULL, kthread_join(thread));

  // Now we should get a challenge ACK.  Note ack of 501, not 601.
  SEND_PKT(&c1, SYN_PKT(/* seq */ 600, /* wndsize */ 8000));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));

  char addr[SOCKADDR_PRETTY_LEN];
  c1.socket = do_accept(s.socket, addr);
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ(DST_IP ":1002", addr);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));

  SEND_PKT(&c1, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 504));
  KEXPECT_STREQ("abc", do_read(c1.socket));
  KEXPECT_TRUE(do_standard_finish(&c1, 0, 3));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

// TODO(smp): Race condition deadlock tests (ideally, can't really test
// currently without SMP)
//  - close with pending socket locked
//  - close with established socket locked

static void listen_tests(void) {
  basic_listen_test();
  listen_queue_max_test();
  listen_backlog_values_test();
  accept_blocks_test();
  accept_blocks_test2();
  accept_blocks_test3();
  listen_on_any_addr_test();
  accept_address_params_test();
  accept_child_rst1();
  accept_child_rst2();
  accept_child_rst3();
  accept_child_rst4();
  accept_child_rst5();
  accept_child_partial_close();
  accept_child_partial_close2();
  syn_during_listen_close_test();
  syn_during_listen_close_test2();
  simultaneous_connections_same_5tuple();
}

static void poll_read_test(void) {
  KTEST_BEGIN("TCP: poll(POLLIN) - readable data");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  // Once data is available, the poll() should trigger.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 506));

  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, poll_op.events);

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);

  // Read some, but not all, of the data.
  KEXPECT_STREQ("abc", do_read_len(s.socket, 3));

  // POLLIN should still trigger.
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);

  KEXPECT_STREQ("de", do_read(s.socket));

  // poll should hang again.
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI));

  // Send FIN.
  SEND_PKT(&s, FIN_PKT(/* seq */ 506, /* ack */ 101));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 507));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, poll_op.events);
  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 507));
  SEND_PKT(&s, ACK_PKT(/* seq */ 507, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void poll_shutdown_read_test(void) {
  KTEST_BEGIN("TCP: poll(POLLIN) - shutdown(SHUT_RD)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI));
  // shutdown() should trigger the EOF poll event.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, poll_op.events);
  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);
}

static void poll_write_test(void) {
  KTEST_BEGIN("TCP: poll(POLLOUT) - writable socket");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(int)));

  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI |
                              KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  // As soon as the connect() finishes, we should be considered writable.
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, poll_op.events);

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI | KPOLLOUT |
               KPOLLWRNORM | KPOLLWRBAND;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, pfd.revents);

  // Fill up the send buffer.
  KEXPECT_EQ(5, vfs_write(s.socket, "1234567890", 10));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));
  // Don't ack (yet).

  // A new poll() should block.
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI |
                              KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND));

  pfd.revents = 0;
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(0, pfd.revents);

  // On a duplicate ACK, poll should still be blocking.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  // When we ACK, the poll should finish.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 103));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, poll_op.events);

  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, pfd.revents);

  // Send more data.
  KEXPECT_EQ(2, vfs_write(s.socket, "67890", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "67"));
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));

  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 108));

  KEXPECT_TRUE(do_standard_finish(&s, 7, 0));
  cleanup_tcp_test(&s);
}

static void poll_write_shutdown_test(void) {
  KTEST_BEGIN("TCP: poll(POLLOUT) - shutdown(SHUT_WR)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(int)));

  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI |
                              KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  // As soon as the connect() finishes, we should be considered writable.
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, poll_op.events);

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI | KPOLLOUT |
               KPOLLWRNORM | KPOLLWRBAND;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, pfd.revents);

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  pfd.revents = 0;
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(0, pfd.revents);
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));

  cleanup_tcp_test(&s);
}

static void poll_rdwr_shutdown_test(void) {
  KTEST_BEGIN("TCP: poll() - shutdown(SHUT_RDWR)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(int)));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI | KPOLLOUT |
               KPOLLWRNORM | KPOLLWRBAND;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, pfd.revents);

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 500));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));

  cleanup_tcp_test(&s);
}

static void poll_accept_test(void) {
  KTEST_BEGIN("TCP: poll() on listening socket");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI |
                              KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND));

  KEXPECT_EQ(0, net_listen(s.socket, 10));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  // Send a SYN, complete the connection.
  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 1000);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));

  // Should be in SYN_RCVD, but poll shouldn't finish yet.
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, poll_op.events);

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI | KPOLLOUT |
               KPOLLWRNORM | KPOLLWRBAND;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 2000));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);

  // We should be able to accept() a child socket.
  char addr[SOCKADDR_PRETTY_LEN];
  c1.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ(DST_IP ":1000", addr);
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // Should no longer show readable.
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));

  SEND_PKT(&c1, RST_PKT(/* seq */ 501, /* ack */ 101));
  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void poll_error_test(void) {
  KTEST_BEGIN("TCP: poll() - error");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_FALSE(ntfn_await_with_timeout(&poll_op.done, BLOCK_VERIFY_MS));

  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLERR, poll_op.events);

  struct apos_pollfd pfd;
  pfd.fd = s.socket;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 2000));
  KEXPECT_EQ(KPOLLERR, pfd.revents);

  // Read to clear the error.  Then we should get a read poll for EOF.
  char buf;
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, &buf, 1));
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 0));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, pfd.revents);
  KEXPECT_EQ(0, vfs_read(s.socket, &buf, 1));

  cleanup_tcp_test(&s);
}

static void poll_tests(void) {
  poll_read_test();
  poll_shutdown_read_test();
  poll_write_test();
  poll_write_shutdown_test();
  poll_rdwr_shutdown_test();
  poll_accept_test();
  poll_error_test();
}

static void basic_retransmit_test(void) {
  KTEST_BEGIN("TCP: basic data retransmit");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_LT(get_rto(s.socket), 2000);

  set_rto(s.socket, 40);
  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 504));

  ksleep(200);
  SEND_PKT(&s, ACK_PKT(/* seq */ 504, /* ack */ 106));

  // We should have gotten at least two retransmits.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "12345"));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 504, "12345"));
  KEXPECT_LT(get_rto(s.socket), 1000);
  set_rto(s.socket, 1000);
  KEXPECT_LT(raw_drain_packets(&s), 4);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 106));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 106, /* ack */ 505));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 106, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(505, /* ack */ 107));

  cleanup_tcp_test(&s);
}

static void basic_retransmit_test2(void) {
  KTEST_BEGIN("TCP: basic data retransmit (no retransmit needed)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_LT(get_rto(s.socket), 2000);

  set_rto(s.socket, 20);
  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));
  KEXPECT_LT(get_rto(s.socket), 100);

  ksleep(50);
  KEXPECT_EQ(0, raw_drain_packets(&s));
  KEXPECT_LT(get_rto(s.socket), 100);
  set_rto(s.socket, 1000);

  KEXPECT_TRUE(do_standard_finish(&s, 5, 0));
  cleanup_tcp_test(&s);
}

static void basic_retransmit_test3(void) {
  KTEST_BEGIN(
      "TCP: basic data retransmit (retransmit reset when only some segments "
      "ACK'd)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  set_rto(s.socket, 300);
  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "123"));
  KEXPECT_EQ(2, vfs_write(s.socket, "45", 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "45"));

  ksleep(250);
  // Ack only the first segment.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  ksleep(100);
  // The RTO should have been reset --- and the second one not retransmitted.
  KEXPECT_EQ(0, raw_drain_packets(&s));

  // After a total of 350 ms, the second one should retransmit as well.
  ksleep(250);
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "45"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));

  set_rto(s.socket, 1000);

  KEXPECT_TRUE(do_standard_finish(&s, 5, 0));
  cleanup_tcp_test(&s);
}

static void basic_retransmit_test4(void) {
  KTEST_BEGIN("TCP: basic data retransmit (multi- and partial-segment ACK)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Transmit three segments, then ack the first 2.5 of them.  The full third
  // segment should get retransmitted.
  set_rto(s.socket, 40);
  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "123"));
  KEXPECT_EQ(2, vfs_write(s.socket, "45", 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "45"));
  KEXPECT_EQ(3, vfs_write(s.socket, "678", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "678"));

  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 108));

  ksleep(80);
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 108, /* ack */ 501, "8"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 109));

  // The RTO should have been reset --- and the second one not retransmitted.
  KEXPECT_LT(raw_drain_packets(&s), 2);

  set_rto(s.socket, 1000);

  KEXPECT_TRUE(do_standard_finish(&s, 8, 0));
  cleanup_tcp_test(&s);
}

static void retransmit_syn_test(void) {
  KTEST_BEGIN("TCP: SYN retransmit (connect())");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  set_rto(s.socket, 10);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));

  ksleep(50);
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_LT(raw_drain_packets(&s), 4);

  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_EQ(3000, get_rto(s.socket));

  set_rto(s.socket, 1000);
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);
}

static void retransmit_synack_test(void) {
  KTEST_BEGIN("TCP: retransmit SYN/ACK (listen/accept)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, NULL, 0);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_EQ(0, net_listen(s.socket, 10));

  // Send a SYN, complete the connection.
  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 2000);
  set_rto(s.socket, 10);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 0));

  ksleep(40);
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 0));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 0));
  KEXPECT_LT(raw_drain_packets(&s), 4);

  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_EQ(3000, get_rto(c1.socket));

  KEXPECT_TRUE(do_standard_finish(&c1, 0, 0));
  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
}

static void retransmit_synack_test2(void) {
  KTEST_BEGIN("TCP: SYN/ACK retransmit (simultaneous connect)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  set_rto(s.socket, 40);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));

  // We should get a SYN-ACK back.
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_RCVD", get_sock_state(s.socket));

  ksleep(50);
  EXPECT_PKT(&s, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  KEXPECT_LT(raw_drain_packets(&s), 4);

  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_EQ(3000, get_rto(s.socket));

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  cleanup_tcp_test(&s);
}

static void retransmit_fin_test(void) {
  KTEST_BEGIN("TCP: retransmit FIN (active close)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Shutdown the connection from this side.
  set_rto(s.socket, 10);
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));

  ksleep(20);
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_LT(raw_drain_packets(&s), 4);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  KEXPECT_STREQ("TIME_WAIT", get_sock_state(s.socket));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));

  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  cleanup_tcp_test(&s);
}

static void retransmit_fin_test2(void) {
  KTEST_BEGIN("TCP: retransmit FIN (passive close)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));

  // Should get an ACK.
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 502));

  // Shutdown the connection from this side.
  set_rto(s.socket, 10);
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  ksleep(20);
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_LT(raw_drain_packets(&s), 4);

  SEND_PKT(&s, ACK_PKT(502, /* ack */ 102));

  cleanup_tcp_test(&s);
}

static void fast_retransmit_test(void) {
  KTEST_BEGIN("TCP: fast retransmit (duplicate ACKs) basic test");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "123"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // Send a bunch of "duplicate" ACKs --- they should not _count_ as duplicate
  // ACKs for the purposes of retransmits since there is no outstanding data.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send new data.
  KEXPECT_EQ(3, vfs_write(s.socket, "456", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 501, "456"));

  // Send two duplicate ACKs.  These should increment the counter but not
  // trigger a retransmit.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send a bunch of ACKs that are duplicates sequence-number-wise, but don't
  // count for other reasons.  These should neither increment, nor reset, the
  // counter.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 104, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 504));

  // Try SYNs and FINs.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 501, /* ack */ 104, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 504));
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 104));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 107, /* ack */ 505));

  // Try old ACKs.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 101));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 103));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Try a duplicate ACK that updates the window.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 1000));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));

  // We should not have received a retransmit.
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send more data.
  KEXPECT_EQ(1, vfs_write(s.socket, "7", 1));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 107, /* ack */ 505, "7"));
  KEXPECT_EQ(1, vfs_write(s.socket, "8", 1));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 108, /* ack */ 505, "8"));

  int orig_cwnd = get_cwnd(s.socket);

  // Now send a third proper duplicate ACK.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));

  // ...we should now get a retransmit.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 104, /* ack */ 505, "456"));

  int new_cwnd = get_cwnd(s.socket);
  KEXPECT_LT(new_cwnd, orig_cwnd);

  // Send more duplicate ACKs.  Each one should inflate the cwnd by MSS, but not
  // trigger a retransmit.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(new_cwnd + DEFAULT_MSS, get_cwnd(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(new_cwnd + 2 * DEFAULT_MSS, get_cwnd(s.socket));

  // A non-dup-ACK should not trigger a retransmit, nor reset the counter.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 1000));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(new_cwnd + 2 * DEFAULT_MSS, get_cwnd(s.socket));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 1000));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(new_cwnd + 3 * DEFAULT_MSS, get_cwnd(s.socket));

  // Finally, ACK the data.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 109));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(2 * DEFAULT_MSS,
             get_cwnd(s.socket));  // cwnd should be deflated again.

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 109, /* ack */ 505));
  SEND_PKT(&s, ACK_PKT(505, /* ack */ 110));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

// This tests fast retransmits of FINs.  This shouldn't happen in a normal TCP
// session (as there shouldn't be any additional segments sent after the FIN to
// trigger duplicate ACKs), but test it anyway to make sure the stack handles it
// gracefully.
static void fast_retransmit_test2(void) {
  KTEST_BEGIN("TCP: fast retransmit (duplicate ACKs) FIN test");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(3, vfs_write(s.socket, "123", 3));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "123"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));

  // Send a bunch of "duplicate" ACKs --- they should not _count_ as duplicate
  // ACKs for the purposes of retransmits since there is no outstanding data.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send FIN.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 501));

  // Send two duplicate ACKs.  These should increment the counter but not
  // trigger a retransmit.
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 104));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Send a bunch of ACKs that are duplicates sequence-number-wise, but don't
  // count for other reasons.  These should neither increment, nor reset, the
  // counter.
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 104, "abc"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 105, /* ack */ 504));

  // Try SYNs and FINs.
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 501, /* ack */ 104, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 105, /* ack */ 504));
  SEND_PKT(&s, FIN_PKT(/* seq */ 504, /* ack */ 104));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 105, /* ack */ 505));

  // Try old ACKs.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 101));
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 103));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Try a duplicate ACK that updates the window.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 1000));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));

  // We should not have received a retransmit.
  KEXPECT_FALSE(raw_has_packets(&s));

  // Now send a third proper duplicate ACK.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));

  // ...we should now get a retransmit.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 104, /* ack */ 505));

  // Send more duplicate ACKs.  Each one should NOT trigger a retransmit.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, ACK_PKT2(/* seq */ 505, /* ack */ 104, /* wndsize */ 2000));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Finally, ACK the FIN.
  SEND_PKT(&s, ACK_PKT(/* seq */ 505, /* ack */ 105));
  KEXPECT_FALSE(raw_has_packets(&s));

  kill_time_wait(s.socket);
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void retransmit_tests(void) {
  basic_retransmit_test();
  basic_retransmit_test2();
  if (RUN_SLOW_TIMING_TESTS) {
    basic_retransmit_test3();
    basic_retransmit_test4();
  }
  retransmit_syn_test();
  retransmit_synack_test();
  retransmit_synack_test2();
  retransmit_fin_test();
  retransmit_fin_test2();
  fast_retransmit_test();
  fast_retransmit_test2();
}

static void nonblocking_connect_test(void) {
  KTEST_BEGIN("TCP: non-blocking connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  vfs_make_nonblock(s.socket);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_EQ(-EINPROGRESS, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_TRUE(start_poll(&s.op, s.socket, KPOLLOUT));

  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP_2, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(1, finish_op(&s));
  KEXPECT_EQ(KPOLLOUT, s.op.events);

  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void nonblocking_connect_test2(void) {
  KTEST_BEGIN("TCP: non-blocking connect() (connection reset)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  vfs_make_nonblock(s.socket);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_EQ(-EINPROGRESS, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_TRUE(start_poll(&s.op, s.socket, KPOLLOUT));

  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP, 0x5678));
  KEXPECT_EQ(-EALREADY, do_connect(s.socket, DST_IP_2, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 101));

  KEXPECT_EQ(1, finish_op(&s));
  KEXPECT_EQ(KPOLLERR, s.op.events);

  KEXPECT_EQ(ECONNREFUSED, get_so_error(s.socket));
  KEXPECT_EQ(0, get_so_error(s.socket));

  cleanup_tcp_test(&s);
}

static void nonblocking_accept_test(void) {
  KTEST_BEGIN("TCP: non-blocking accept()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  vfs_make_nonblock(s.socket);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  KEXPECT_EQ(-EAGAIN, net_accept(s.socket, NULL, NULL));
  KEXPECT_EQ(-EAGAIN, net_accept(s.socket, NULL, NULL));
  char addr[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(-EAGAIN, do_accept(s.socket, addr));

  // Start a connection.
  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, DST_IP, 2000);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1,
             SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));

  KEXPECT_EQ(-EAGAIN, do_accept(s.socket, addr));

  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));

  // We should be able to accept() a child socket.
  c1.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ(DST_IP ":2000", addr);
  KEXPECT_EQ(-EAGAIN, do_accept(s.socket, addr));

  KEXPECT_TRUE(do_standard_finish(&c1, 0, 0));

  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&s);
}

static void nonblocking_recvfrom_test(void) {
  KTEST_BEGIN("TCP: non-blocking recvfrom()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_setsockopt_int(s.socket, SOL_SOCKET, SO_RCVBUF, 500));
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

    KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  vfs_make_nonblock(s.socket);
  async_op_t poll_op;
  KEXPECT_TRUE(start_poll(&poll_op, s.socket,
                          KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI));

  char buf[10];
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 10));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abcde"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 506));

  KEXPECT_EQ(1, finish_op_direct(&poll_op));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, poll_op.events);

  KEXPECT_EQ(2, vfs_read(s.socket, buf, 2));
  KEXPECT_EQ(3, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 10));

  SEND_PKT(&s, DATA_PKT(/* seq */ 506, /* ack */ 101, "123"));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 509));
  KEXPECT_EQ(1, vfs_read(s.socket, buf, 1));
  KEXPECT_EQ(2, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(-EAGAIN, vfs_read(s.socket, buf, 10));

  // Test what happens when there's an error.
  SEND_PKT(&s, RST_PKT(/* seq */ 509, /* ack */ 101));
  KEXPECT_EQ(-ECONNRESET, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  cleanup_tcp_test(&s);
}

static void nonblocking_send_test(void) {
  KTEST_BEGIN("TCP: non-blocking socket sendto");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  int val = 5;
  KEXPECT_EQ(
      0, net_setsockopt(s.socket, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  vfs_make_nonblock(s.socket);

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

  // The next write _would_ block, but shouldn't.
  KEXPECT_EQ(-EAGAIN, vfs_write(s.socket, "ilmn", 4));

  // Finally send an ACK. [abcd] [] [efgh]
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 105, /* wndsize */ 3));

  // We should get three more bytes from the buffer.  [abcd] [efg] [h]
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 105, /* ack */ 501, "efg"));
  // ...don't ack yet.

  // We should now be able to write one more byte.
  KEXPECT_EQ(1, vfs_write(s.socket, "ilmn", 4));
  KEXPECT_EQ(-EAGAIN, vfs_write(s.socket, "lmn", 3));

  // Ack things and get the rest.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 108, /* wndsize */ 100));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 108, /* ack */ 501, "hi"));
  KEXPECT_FALSE(raw_has_packets_wait(&s, BLOCK_VERIFY_MS));

  // We should still be able to get an error.
  SEND_PKT(&s, RST_PKT(/* seq */ 501, /* ack */ 108));
  KEXPECT_EQ(-ECONNRESET, vfs_write(s.socket, "abc", 3));

  // We should still be able to get an EPIPE.
  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void nonblocking_tests(void) {
  nonblocking_connect_test();
  nonblocking_connect_test2();
  nonblocking_accept_test();
  nonblocking_recvfrom_test();
  nonblocking_send_test();
}

static void shutdown_test_point_hook(const char* name, int count, void* arg) {
  KEXPECT_EQ(0, net_shutdown((intptr_t)arg, SHUT_RDWR));
}

static void send_rst_test_point_hook(const char* name, int count, void* arg) {
  if (count > 0) {
    return;
  }
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, RST_PKT(/* seq */ 501, /* ack */ 101));
}

static void fin_and_shutdown_test_point_hook(const char* name, int count,
                                             void* arg) {
  if (count > 0) {
    return;
  }
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(s, ACK_PKT(/* seq */ 101, /* ack */ 502));
  KEXPECT_EQ(0, net_shutdown(s->socket, SHUT_WR));
  EXPECT_PKT(s, FIN_PKT(/* seq */ 101, /* ack */ 502));
  SEND_PKT(s, ACK_PKT(/* seq */ 502, /* ack */ 102));
}

// As above, but expects some data to be sent with the first ACK.
static void fin_and_shutdown_test_point_hook_data(const char* name, int count,
                                                  void* arg) {
  if (count > 0) {
    return;
  }
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(s, DATA_PKT(/* seq */ 101, /* ack */ 502, "abc"));
  KEXPECT_EQ(0, net_shutdown(s->socket, SHUT_WR));
  EXPECT_PKT(s, FIN_PKT(/* seq */ 104, /* ack */ 502));
  SEND_PKT(s, ACK_PKT(/* seq */ 502, /* ack */ 105));
}

// As above, but offsets the remote seq by 3 to reflect data sent.
static void fin_and_shutdown_test_point_hook_data_sent(const char* name,
                                                       int count, void* arg) {
  if (count > 0) {
    return;
  }
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, FIN_PKT(/* seq */ 504, /* ack */ 101));
  EXPECT_PKT(s, ACK_PKT(/* seq */ 101, /* ack */ 505));
  KEXPECT_EQ(0, net_shutdown(s->socket, SHUT_WR));
  EXPECT_PKT(s, FIN_PKT(/* seq */ 101, /* ack */ 505));
  SEND_PKT(s, ACK_PKT(/* seq */ 505, /* ack */ 102));
}

// Test hook that forces a socket in TIME_WAIT to close.
static void close_time_wait_socket_hook(const char* name, int count,
                                        void* arg) {
  int fd = (intptr_t)arg;
  kill_time_wait(fd);
}

static void close_dispatch_race_test(void) {
  KTEST_BEGIN("TCP: socket closes during packet dispatch");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RDWR));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 101, /* ack */ 501));
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 102));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 102, /* ack */ 502));

  test_point_add("tcp:dispatch_packet", &close_time_wait_socket_hook,
                 (void*)(intptr_t)s.socket);
  SEND_PKT(&s, RST_PKT(/* seq */ 502, /* ack */ 102));
  KEXPECT_EQ(1, test_point_remove("tcp:dispatch_packet"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void close_syn_sent_race_test(void) {
  KTEST_BEGIN("TCP: socket closes from SYN_SENT before RST sent");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  test_point_add("tcp:dispatch_packet_action", &shutdown_test_point_hook,
                 (void*)(intptr_t)s.socket);

  // Send a plain ACK to get a RST.
  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 100));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 100));
  KEXPECT_EQ(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  // TODO(aoates): should this return ECONNABORTED?
  KEXPECT_EQ(0, finish_op(&s));

  cleanup_tcp_test(&s);
}

static void finish_conn_test_point_hook(const char* name, int count,
                                        void* arg) {
  if (count > 0) {
    return;
  }
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(s, ACK_PKT(/* seq */ 101, /* ack */ 501));
}

static void close_syn_sent_race_test2(void) {
  KTEST_BEGIN("TCP: socket connection finishes in SYN_SENT before RST sent");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  test_point_add("tcp:dispatch_packet_action", &finish_conn_test_point_hook,
                 &s);

  // Send a plain ACK to get a RST.
  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 100));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 100));
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  KEXPECT_EQ(0, finish_op(&s));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));

  cleanup_tcp_test(&s);
}

static void close_syn_sent_race_test3(void) {
  KTEST_BEGIN("TCP: socket closes during simultaneous connect from SYN_SENT");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  test_point_add("tcp:dispatch_packet_action",
                 &fin_and_shutdown_test_point_hook, &s);

  // Send a simultaneous SYN to get to SYN_RCVD and retransmit the original SYN
  // as a SYN/ACK (if we didn't close first).
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));
  KEXPECT_EQ(0, finish_op(&s));

  cleanup_tcp_test(&s);
}

static void close_handle_urg_race_test(void) {
  KTEST_BEGIN("TCP: socket closes after getting URG data before reset sent");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  test_point_add("tcp:dispatch_packet_action",
                 &fin_and_shutdown_test_point_hook, &s);

  SEND_PKT(&s, URG_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  // Note: this _should_ send a RST --- if the close happens before the URG
  // packet is received, it would be a no-matching-socket RST; if after the
  // packet is handled, it would be a get-URG RST.  In the case of the race
  // condition here, we  match the packet, the fail to send the RST because the
  // socket closes.  I think that's fine behavior given how rare this should be.
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void close_handle_data_after_shutdown_race_test(void) {
  KTEST_BEGIN(
      "TCP: socket closes after getting post-shutdown data before reset sent");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  test_point_add("tcp:dispatch_packet_action",
                 &fin_and_shutdown_test_point_hook, &s);

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));
  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  // As above, this _should_ send a RST.
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void close_send_data_after_shutdown_race_test(void) {
  KTEST_BEGIN("TCP: socket closes before sending data");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ WNDSIZE_ZERO));
  KEXPECT_EQ(3, vfs_write(s.socket, "abc", 3));

  test_point_add("tcp:dispatch_packet_action",
                 &fin_and_shutdown_test_point_hook_data, &s);

  // Open the window and trigger the send data/close race.
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 101, /* wndsize */ 100));
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void close_get_data_after_shutdown_race_test(void) {
  KTEST_BEGIN("TCP: socket closes before sending ACK");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  test_point_add("tcp:dispatch_packet_action",
                 &fin_and_shutdown_test_point_hook_data_sent, &s);

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void close_get_fin_after_shutdown_race_test(void) {
  KTEST_BEGIN("TCP: socket (gets FIN) closes before sending ACK");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  test_point_add("tcp:dispatch_packet_action",
                 &fin_and_shutdown_test_point_hook, &s);

  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_LT(1, test_point_remove("tcp:dispatch_packet_action"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void shutdown_and_close_race_test(void) {
  KTEST_BEGIN("TCP: socket in shutdown() closes before sending FIN");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  test_point_add("tcp:shutdown_before_send", &send_rst_test_point_hook, &s);

  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(1, test_point_remove("tcp:shutdown_before_send"));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void close_race_tests(void) {
  close_dispatch_race_test();
  close_syn_sent_race_test();
  close_syn_sent_race_test2();
  close_syn_sent_race_test3();
  close_handle_urg_race_test();
  close_handle_data_after_shutdown_race_test();
  close_send_data_after_shutdown_race_test();
  close_get_data_after_shutdown_race_test();
  close_get_fin_after_shutdown_race_test();
  shutdown_and_close_race_test();
}

static void send_rst100_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, RST_PKT(/* seq */ 501, /* ack */ 100));
}

static void send_rst101_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, RST_PKT(/* seq */ 501, /* ack */ 101));
}

static void send_synack100_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, SYNACK_PKT(/* seq */ 500, /* ack */ 100, /* wndsize */ 8000));
}

static void send_synack101_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
}

static void send_ack100_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, ACK_PKT(/* seq */ 501, /* ack */ 100));
}

static void send_ack101_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, ACK_PKT(/* seq */ 501, /* ack */ 101));
}

static void shutdown_tp_hook(const char* name, int count, void* arg) {
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  net_shutdown(s->socket, SHUT_RD);
  net_shutdown(s->socket, SHUT_WR);
}

// We have two versions of each test, one that sends with an ACK value of 100
// and one with 101 --- this is to make sure we tickle interesting races,
// regardless of whether the internal TCP code increments it's send_next before
// or after unlocking the mutex.
//
// The specific outcome isn't necessarily important so long as it's valid and
// safe.
static void open_connect_rst_test(void) {
  KTEST_BEGIN("TCP: socket gets RST during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  // This RST should be ignored.
  test_point_add("tcp:send_syn", &send_rst100_tp_hook, &s);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_EQ(0, test_point_remove("tcp:send_syn"));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(0, s.op.result);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void open_connect_rst_test2(void) {
  KTEST_BEGIN("TCP: socket gets RST during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  test_point_add("tcp:send_syn", &send_rst101_tp_hook, &s);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_EQ(0, test_point_remove("tcp:send_syn"));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(0, s.op.result);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(s.socket));
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

// This shouldn't happen in a normal connection (the peer would have to guess
// our sequence number).
static void open_connect_established_race_test(void) {
  KTEST_BEGIN("TCP: socket gets a SYN/ACK before sending SYN during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  test_point_add("tcp:send_syn", &send_synack100_tp_hook, &s);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_EQ(0, test_point_remove("tcp:send_syn"));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(0, s.op.result);
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void open_connect_established_race_test2(void) {
  KTEST_BEGIN(
      "TCP: socket gets a SYN/ACK before sending SYN during connect() (#2)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  test_point_add("tcp:send_syn", &send_synack101_tp_hook, &s);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_EQ(0, test_point_remove("tcp:send_syn"));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(0, s.op.result);
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void open_connect_shutdown_test(void) {
  KTEST_BEGIN("TCP: socket gets shutdown during connect()");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  // This RST should be ignored.
  test_point_add("tcp:send_syn", &shutdown_tp_hook, &s);
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_EQ(0, test_point_remove("tcp:send_syn"));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));
  KEXPECT_TRUE(finish_standard_connect(&s));
  KEXPECT_EQ(0, s.op.result);
  KEXPECT_TRUE(do_standard_finish(&s, 0, 0));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
}

static void open_accept_rst_test(void) {
  KTEST_BEGIN("TCP: socket gets RST during inbound connection");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  // Start a connection.
  test_point_add("tcp:send_syn", &send_rst100_tp_hook, &s);
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  KEXPECT_EQ(1, test_point_remove("tcp:send_syn"));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  cleanup_tcp_test(&s);
}

static void open_accept_rst_test2(void) {
  KTEST_BEGIN("TCP: socket gets RST during inbound connection");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  // Start a connection.
  test_point_add("tcp:send_syn", &send_rst101_tp_hook, &s);
  SEND_PKT(&s, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  KEXPECT_EQ(1, test_point_remove("tcp:send_syn"));
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  cleanup_tcp_test(&s);
}

static void open_accept_established_test(void) {
  KTEST_BEGIN(
      "TCP: socket gets ACK before sending SYN/ACK during inbound connection");
  tcp_test_state_t s, c1;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  init_tcp_test_child(&s, &c1, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  // Start a connection.  The early ACK should be ignored.
  test_point_add("tcp:send_syn", &send_ack100_tp_hook, &s);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  KEXPECT_EQ(1, test_point_remove("tcp:send_syn"));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));

  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_TRUE(do_standard_finish(&c1, 0, 0));

  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&s);
}

static void open_accept_established_test2(void) {
  KTEST_BEGIN(
      "TCP: socket gets ACK before sending SYN/ACK during inbound connection");
  tcp_test_state_t s, c1;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  init_tcp_test_child(&s, &c1, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  // Start a connection.  The early ACK should trigger a challenge ACK.
  test_point_add("tcp:send_syn", &send_ack101_tp_hook, &s);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 100, /* ack */ 501));  // Challenge ACK.
  KEXPECT_EQ(1, test_point_remove("tcp:send_syn"));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));

  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_TRUE(do_standard_finish(&c1, 0, 0));

  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&s);
}

// Note: unlike the open_connect_shutdown_test(), this closes the _listening_
// socket and not the connecting socket.  There's no way to get the connecting
// socket to close it (it doesn't have a file descriptor yet).
static void open_accept_shutdown_test(void) {
  KTEST_BEGIN("TCP: listening socket gets shutdown during inbound connection");
  tcp_test_state_t s, c1;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);
  init_tcp_test_child(&s, &c1, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(0, net_listen(s.socket, 10));

  // Start a connection.  The shutdown will be ignored.
  test_point_add("tcp:send_syn", &shutdown_tp_hook, &s);
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  KEXPECT_EQ(1, test_point_remove("tcp:send_syn"));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  EXPECT_PKT(&c1, SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wnd */ 0));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));

  c1.socket = net_accept(s.socket, NULL, NULL);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_TRUE(do_standard_finish(&c1, 0, 0));

  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&s);
}

static void open_race_tests(void) {
  open_connect_rst_test();
  open_connect_rst_test2();
  open_connect_established_race_test();
  open_connect_established_race_test2();
  open_connect_shutdown_test();
  open_accept_rst_test();
  open_accept_rst_test2();
  open_accept_established_test();
  open_accept_established_test2();
  open_accept_shutdown_test();
}

static void cwnd_test(void) {
  KTEST_BEGIN("TCP cwnd test: initial cwnd");
  tcp_cwnd_t cw;
  tcp_cwnd_init(&cw, 2500);
  KEXPECT_EQ(5000, cw.cwnd);
  tcp_cwnd_init(&cw, 2000);
  KEXPECT_EQ(6000, cw.cwnd);
  tcp_cwnd_init(&cw, 1000);
  KEXPECT_EQ(4000, cw.cwnd);


  KTEST_BEGIN("TCP cwnd test: slow start");
  tcp_cwnd_init(&cw, 1000);
  KEXPECT_EQ(4000, cw.cwnd);
  tcp_cwnd_acked(&cw, 300);
  KEXPECT_EQ(4300, cw.cwnd);
  tcp_cwnd_acked(&cw, 700);
  KEXPECT_EQ(5000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(6000, cw.cwnd);
  tcp_cwnd_acked(&cw, 2000);
  KEXPECT_EQ(7000, cw.cwnd);  // Should be clamped at MSS.
  tcp_cwnd_acked(&cw, 2000);
  KEXPECT_EQ(8000, cw.cwnd);  // Should be clamped at MSS.


  KTEST_BEGIN("TCP cwnd test: congestion avoidance");
  tcp_cwnd_rto(&cw, 7000);
  KEXPECT_EQ(1000, cw.cwnd);  // Should be back to slow start.
  tcp_cwnd_acked(&cw, 2000);
  KEXPECT_EQ(2000, cw.cwnd);
  tcp_cwnd_acked(&cw, 2000);
  KEXPECT_EQ(3000, cw.cwnd);
  tcp_cwnd_acked(&cw, 2000);
  KEXPECT_EQ(4000, cw.cwnd);

  // Now we should be in congestion avoidance.
  tcp_cwnd_acked(&cw, 2000);
  KEXPECT_EQ(4000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(4000, cw.cwnd);
  tcp_cwnd_acked(&cw, 900);
  KEXPECT_EQ(4000, cw.cwnd);
  tcp_cwnd_acked(&cw, 100);
  KEXPECT_EQ(5000, cw.cwnd);

  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(5000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(5000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(5000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(5000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(6000, cw.cwnd);

  // Test clamping of ssthresh if there's little outstanding data.
  tcp_cwnd_rto(&cw, 100);
  KEXPECT_EQ(2000, cw.ssthresh);
  KEXPECT_EQ(1000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(2000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(3000, cw.cwnd);
  tcp_cwnd_acked(&cw, 1000);
  KEXPECT_EQ(3000, cw.cwnd);

  KTEST_BEGIN("TCP: cwnd duplicate ack test");
  tcp_cwnd_init(&cw, 500);
  KEXPECT_EQ(2000, cw.cwnd);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  tcp_cwnd_acked(&cw, 500);
  KEXPECT_EQ(8000, cw.cwnd);

  tcp_cwnd_dupack(&cw, 8000, 1);
  KEXPECT_EQ(8000, cw.cwnd);
  KEXPECT_EQ(INT32_MAX, cw.ssthresh);

  tcp_cwnd_dupack(&cw, 8000, 2);
  KEXPECT_EQ(8000, cw.cwnd);
  KEXPECT_EQ(INT32_MAX, cw.ssthresh);

  tcp_cwnd_dupack(&cw, 8000, 3);
  KEXPECT_EQ(4000, cw.ssthresh);
  KEXPECT_EQ(5500, cw.cwnd);

  // We should inflate the window with additional duplicate ACKs.
  tcp_cwnd_dupack(&cw, 8000, 4);
  KEXPECT_EQ(4000, cw.ssthresh);
  KEXPECT_EQ(6000, cw.cwnd);
  tcp_cwnd_dupack(&cw, 8000, 5);
  KEXPECT_EQ(4000, cw.ssthresh);
  KEXPECT_EQ(6500, cw.cwnd);

  // ...and should deflate the window when data is finally ACK'd.
  tcp_cwnd_acked(&cw, 500);
  KEXPECT_EQ(4000, cw.ssthresh);
  KEXPECT_EQ(4000, cw.cwnd);
}

static void cwnd_socket_test(void) {
  KTEST_BEGIN("TCP: congestion window on socket");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));
  KEXPECT_TRUE(finish_standard_connect(&s));

  int cwnd;
  socklen_t len = sizeof(cwnd);
  KEXPECT_EQ(0,
             net_getsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, &len));
  KEXPECT_GE(cwnd, 500);
  KEXPECT_LE(cwnd, 5000);

  // Test setting CWND.
  cwnd = 10;
  KEXPECT_EQ(0, net_setsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, len));
  KEXPECT_EQ(0,
             net_getsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, &len));
  KEXPECT_EQ(cwnd, 10);

  cwnd = -1;
  KEXPECT_EQ(-EINVAL,
             net_setsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, len));
  KEXPECT_EQ(0,
             net_getsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, &len));
  KEXPECT_EQ(cwnd, 10);

  char* buf = kmalloc(200);
  kmemset(buf, 'x', 200);

  // We should be able to send without blocking.
  KEXPECT_EQ(100, vfs_write(s.socket, buf, 100));

  buf[10] = '\0';
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, buf));
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 111, /* wndsize */ 500));

  // We should now get 2x the data.
  buf[10] = 'x';
  buf[20] = '\0';
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 111, /* ack */ 501, buf));
  set_rto(s.socket, 20);
  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 131, /* wndsize */ 500));
  buf[20] = 'x';
  buf[40] = '\0';
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 131, /* ack */ 501, buf));

  ksleep(50);

  // After several retransmits, we should have reset CWND.
  KEXPECT_EQ(0,
             net_getsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, &len));
  KEXPECT_EQ(cwnd, DEFAULT_MSS);
  cwnd = 20;
  KEXPECT_EQ(0, net_setsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, len));

  // After more retransmits, we should _not_ have reset CWND again.
  ksleep(100);
  KEXPECT_EQ(0,
             net_getsockopt(s.socket, IPPROTO_TCP, SO_TCP_CWND, &cwnd, &len));
  KEXPECT_EQ(cwnd, 20);

  EXPECT_PKT(&s, DATA_PKT(/* seq */ 131, /* ack */ 501, buf));
  raw_drain_packets(&s);

  SEND_PKT(&s, ACK_PKT2(/* seq */ 501, /* ack */ 171, /* wndsize */ 500));
  buf[40] = 'x';
  buf[30] = '\0';
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 171, /* ack */ 501, buf));

  KEXPECT_TRUE(do_standard_finish(&s, 100, 0));
  kfree(buf);
  cleanup_tcp_test(&s);
}

static void nonblocking_tap_test(void) {
  KTEST_BEGIN("TCP: non-blocking connect still blocks for ARP");
  test_ttap_t tap;
  KEXPECT_EQ(0, test_ttap_create(&tap, TUNTAP_TAP_MODE));
  nic_t* nic = tap.n;

  kspin_lock(&nic->lock);
  nic->addrs[0].a.addr.family = ADDR_INET;
  nic->addrs[0].a.addr.a.ip4.s_addr = str2inet(TAP_SRC_IP);
  nic->addrs[0].a.prefix_len = 24;
  nic->addrs[0].state = NIC_ADDR_ENABLED;
  kspin_unlock(&nic->lock);

  tcp_test_state_t s;
  init_tcp_test(&s, TAP_SRC_IP, 0x1234, TAP_DST_IP, 0x5678);
  vfs_make_nonblock(s.socket);
  KEXPECT_EQ(0, do_bind(s.socket, TAP_SRC_IP, 0x1234));

  // We should be able to start an async connect() and it will block because the
  // ARP cache is empty, even though the socket is non-blocking.
  KEXPECT_TRUE(start_connect(&s, TAP_DST_IP, 0x5678));

  // We should have gotten an ARP request.
  char* buf = kmalloc(500);
  kmemset(buf, 0, 500);
  KEXPECT_EQ(sizeof(eth_hdr_t) + 28 /* ARP request */,
             vfs_read(tap.fd, buf, 500));

  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)buf;
  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  char macstr1[NIC_MAC_PRETTY_LEN], macstr2[NIC_MAC_PRETTY_LEN];
  KEXPECT_STREQ(mac2str(nic->mac.addr, macstr1),
                mac2str(eth_hdr->mac_src, macstr2));
  KEXPECT_STREQ("FF:FF:FF:FF:FF:FF", mac2str(eth_hdr->mac_dst, macstr1));

  // Signal to kill the connecting thread.
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  cleanup_tcp_test(&s);


  // Now try again with a blocking socket.
  KTEST_BEGIN("TCP: blocking connect blocks for ARP");
  init_tcp_test(&s, TAP_SRC_IP, 0x1234, TAP_DST_IP, 0x5678);
  KEXPECT_EQ(0, do_bind(s.socket, TAP_SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, TAP_DST_IP, 0x5678));

  // We should have gotten an ARP request.
  kmemset(buf, 0, 500);
  KEXPECT_EQ(sizeof(eth_hdr_t) + 28 /* ARP request */,
             vfs_read(tap.fd, buf, 500));

  KEXPECT_EQ(ET_ARP, btoh16(eth_hdr->ethertype));
  KEXPECT_STREQ(mac2str(nic->mac.addr, macstr1),
                mac2str(eth_hdr->mac_src, macstr2));
  KEXPECT_STREQ("FF:FF:FF:FF:FF:FF", mac2str(eth_hdr->mac_dst, macstr1));

  // Signal to kill the connecting thread.
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));

  cleanup_tcp_test(&s);

  test_ttap_destroy(&tap);
  kfree(buf);
}

// Create a standard TCP socket with options set for tests.
static int make_test_socket(void) {
  int sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(sock, 0);
  // Set it long enough that it will outlive the relevant tests, but not so long
  // that they won't get a chance to fire if there's a bug.
  KEXPECT_EQ(0,
             do_setsockopt_int(sock, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 1000));
  return sock;
}

static void connect_sockets_tests(void) {
  KTEST_BEGIN("TCP: basic self-connect test");
  int server = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(server, 0);
  vfs_make_nonblock(server);
  KEXPECT_EQ(0, do_bind(server, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, net_listen(server, 10));

  int c1 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));

  int s1 = net_accept(server, NULL, NULL);
  KEXPECT_GE(s1, 0);

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  close_time_wait(c1);


  KTEST_BEGIN("TCP: multiple connections to same dest (bound sockets)");
  c1 = make_test_socket();
  KEXPECT_EQ(0, do_bind(c1, LO_SRC_IP, 10000));
  int c2 = make_test_socket();
  KEXPECT_EQ(-EADDRINUSE, do_bind(c2, LO_SRC_IP, 10000));
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));

  KEXPECT_EQ(-EADDRINUSE, do_bind(c2, LO_SRC_IP, 10000));
  KEXPECT_EQ(0, do_bind(c2, LO_SRC_IP, 10001));
  KEXPECT_EQ(0, do_connect(c2, LO_DST_IP, SERVER_PORT));

  s1 = net_accept(server, NULL, NULL);
  KEXPECT_GE(s1, 0);
  int s2 = net_accept(server, NULL, NULL);
  KEXPECT_GE(s2, 0);

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(c2, "def", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_EQ(3, vfs_write(s2, "123", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("123", do_read(c2));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_STREQ("def", do_read(s2));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, net_shutdown(c2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));
  close_time_wait(c1);
  close_time_wait(c2);


  KTEST_BEGIN("TCP: multiple connections to same dest (only one bound)");
  c1 = make_test_socket();
  KEXPECT_EQ(0, do_bind(c1, LO_SRC_IP, 10100));
  c2 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, do_connect(c2, LO_DST_IP, SERVER_PORT));

  char addr1[SOCKADDR_PRETTY_LEN], addr2[SOCKADDR_PRETTY_LEN];
  s1 = do_accept(server, addr1);
  KEXPECT_GE(s1, 0);
  s2 = do_accept(server, addr2);
  KEXPECT_GE(s2, 0);
  KEXPECT_STRNE(addr1, addr2);

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(c2, "def", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_EQ(3, vfs_write(s2, "123", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("123", do_read(c2));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_STREQ("def", do_read(s2));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, net_shutdown(c2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));
  close_time_wait(c1);
  close_time_wait(c2);


  KTEST_BEGIN("TCP: multiple connections to same dest (both unbound)");
  c1 = make_test_socket();
  c2 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, do_connect(c2, LO_DST_IP, SERVER_PORT));

  s1 = do_accept(server, addr1);
  KEXPECT_GE(s1, 0);
  s2 = do_accept(server, addr2);
  KEXPECT_GE(s2, 0);
  KEXPECT_STRNE(addr1, addr2);

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(c2, "def", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_EQ(3, vfs_write(s2, "123", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("123", do_read(c2));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_STREQ("def", do_read(s2));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, net_shutdown(c2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));
  close_time_wait(c1);
  close_time_wait(c2);


  KTEST_BEGIN("TCP: multiple connections to same dest (both any-addr)");
  c1 = make_test_socket();
  c2 = make_test_socket();
  KEXPECT_EQ(0, do_bind(c1, "0.0.0.0", 0));
  KEXPECT_EQ(0, do_bind(c2, "0.0.0.0", 0));
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, do_connect(c2, LO_DST_IP, SERVER_PORT));
  KEXPECT_STREQ(LO_DST_IP_PORT, getpeername_str(c1));
  KEXPECT_STREQ(LO_DST_IP_PORT, getpeername_str(c2));

  s1 = do_accept(server, addr1);
  KEXPECT_GE(s1, 0);
  s2 = do_accept(server, addr2);
  KEXPECT_GE(s2, 0);
  KEXPECT_STRNE(addr1, addr2);


  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(c2, "def", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_EQ(3, vfs_write(s2, "123", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("123", do_read(c2));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_STREQ("def", do_read(s2));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, net_shutdown(c2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));
  close_time_wait(c1);
  close_time_wait(c2);


  KTEST_BEGIN("TCP: bound to any-port");
  c1 = make_test_socket();
  KEXPECT_EQ(0, do_bind(c1, LO_SRC_IP, 0));
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  KEXPECT_STRNE(LO_SRC_IP ":0", getsockname_str(c1));
  KEXPECT_STREQ(LO_DST_IP_PORT, getpeername_str(c1));

  s1 = do_accept(server, addr1);
  KEXPECT_GE(s1, 0);
  kstrcpy(addr1, getsockname_str(c1));
  KEXPECT_STREQ(addr1, getpeername_str(s1));

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  close_time_wait(c1);


  KTEST_BEGIN("TCP: bound to any-addr + port");
  c1 = make_test_socket();
  KEXPECT_EQ(0, do_bind(c1, "0.0.0.0", 12345));
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  KEXPECT_STRNE(LO_SRC_IP ":12345", getsockname_str(c1));
  KEXPECT_STREQ(LO_DST_IP_PORT, getpeername_str(c1));

  s1 = do_accept(server, addr1);
  KEXPECT_GE(s1, 0);
  kstrcpy(addr1, getsockname_str(c1));
  KEXPECT_STREQ(addr1, getpeername_str(s1));

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  close_time_wait(c1);


  KTEST_BEGIN("TCP: connection that outlives server socket");
  c1 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));

  s1 = do_accept(server, addr1);
  KEXPECT_GE(s1, 0);

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_EQ(3, vfs_write(s1, "xyz", 3));
  KEXPECT_STREQ("xyz", do_read(c1));
  KEXPECT_STREQ("abc", do_read(s1));

  KEXPECT_EQ(0, vfs_close(server));

  KEXPECT_EQ(3, vfs_write(c1, "ABC", 3));
  KEXPECT_EQ(3, vfs_write(s1, "XYZ", 3));
  KEXPECT_STREQ("XYZ", do_read(c1));
  KEXPECT_STREQ("ABC", do_read(s1));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  close_time_wait(c1);
}

static void reuseaddr_tests(void) {
  KTEST_BEGIN("TCP: SO_REUSEADDR test");
  int server = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(server, 0);
  vfs_make_nonblock(server);
  KEXPECT_EQ(0, do_bind(server, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, net_listen(server, 10));

  int s2 = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  int val = 123;
  socklen_t val_len = sizeof(val);
  KEXPECT_EQ(0, net_getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &val, &val_len));
  KEXPECT_EQ(0, val);

  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, "0.0.0.0", SERVER_PORT));
  KEXPECT_EQ(0, do_setsockopt_int(s2, SOL_SOCKET, SO_REUSEADDR, 5));

  KEXPECT_EQ(0, net_getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &val, &val_len));
  KEXPECT_EQ(1, val);

  KEXPECT_EQ(0, do_setsockopt_int(s2, SOL_SOCKET, SO_REUSEADDR, 0));
  KEXPECT_EQ(0, net_getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &val, &val_len));
  KEXPECT_EQ(0, val);

  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, "0.0.0.0", SERVER_PORT));
  KEXPECT_EQ(0, do_setsockopt_int(s2, SOL_SOCKET, SO_REUSEADDR, 1));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, do_bind(s2, "0.0.0.0", SERVER_PORT));
  KEXPECT_EQ(0, vfs_close(s2));
  s2 = -1;

  int c1 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));

  int s1 = net_accept(server, NULL, NULL);
  KEXPECT_EQ(0, do_setsockopt_int(s1, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 1000));
  KEXPECT_GE(s1, 0);

  KEXPECT_EQ(0, vfs_close(server));

  struct sockaddr_in c1_addr;
  KEXPECT_EQ(0, getsockname_inet(c1, &c1_addr));

  // Binding to the local address (server or client) should fail.
  s2 = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(s2, (struct sockaddr*)&c1_addr, sizeof(c1_addr)));
  KEXPECT_EQ(0, do_setsockopt_int(s2, SOL_SOCKET, SO_REUSEADDR, 1));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(s2, (struct sockaddr*)&c1_addr, sizeof(c1_addr)));
  KEXPECT_EQ(0, do_setsockopt_int(s2, SOL_SOCKET, SO_REUSEADDR, 0));

  // After the client socket enters TIME_WAIT, we should be able to.
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RDWR));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(-EADDRINUSE, do_bind(s2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, do_setsockopt_int(s2, SOL_SOCKET, SO_REUSEADDR, 1));
  KEXPECT_EQ(0, do_bind(s2, LO_DST_IP, SERVER_PORT));

  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(0, vfs_close(c1));
  close_time_wait(s1);


  KTEST_BEGIN("TCP: connect() fails due to in-use address");
  server = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_EQ(0, do_setsockopt_int(server, SOL_SOCKET, SO_REUSEADDR, 1));
  KEXPECT_GE(server, 0);
  vfs_make_nonblock(server);
  KEXPECT_EQ(0, do_bind(server, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, net_listen(server, 10));

  c1 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));

  s1 = net_accept(server, NULL, NULL);
  KEXPECT_EQ(0, do_setsockopt_int(s1, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 1000));
  KEXPECT_GE(s1, 0);

  // Get the c1 address and put s1 into TIME_WAIT.
  KEXPECT_EQ(0, getsockname_inet(c1, &c1_addr));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RDWR));
  KEXPECT_EQ(0, net_shutdown(c1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(server));
  server = -1;

  // Now create another socket and bind it to the same local address as the
  // server was bound to.
  int c2 = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(c2, 0);
  KEXPECT_EQ(-EADDRINUSE, do_bind(c2, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, do_setsockopt_int(c2, SOL_SOCKET, SO_REUSEADDR, 1));
  KEXPECT_EQ(0, do_bind(c2, LO_DST_IP, SERVER_PORT));

  // Now connect() c2 to the address c1 was bound to.  This should fail, since
  // the 5-tuple is already taken by c1 (which is in TIME_WAIT).
  KEXPECT_STREQ("CLOSED", get_sock_state(c2));
  KEXPECT_EQ(-EADDRINUSE,
             net_connect(c2, (struct sockaddr*)&c1_addr, sizeof(c1_addr)));
  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(c2));

  close_time_wait(s1);
  KEXPECT_EQ(0, vfs_close(c1));
  KEXPECT_EQ(0, vfs_close(c2));
}

static void rapid_reconnect_test(void) {
  KTEST_BEGIN("TCP: rapid reconnection to the same IP:port");
  int server = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(server, 0);
  vfs_make_nonblock(server);
  KEXPECT_EQ(0, do_bind(server, LO_DST_IP, SERVER_PORT));
  KEXPECT_EQ(0, net_listen(server, 10));

  // If we select the same port twice in a row, then the second connection will
  // send a SYN to the TIME_WAIT socket, which will send back a challenge ACK,
  // which will trigger a RST (and close the TIME_WAIT socket); then a
  // retransmitted SYN will start the new connection 1s later.
  int c1 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  struct sockaddr_in c1_addr;
  KEXPECT_EQ(0, getsockname_inet(c1, &c1_addr));

  int s1 = net_accept(server, NULL, NULL);
  KEXPECT_EQ(0, do_setsockopt_int(s1, IPPROTO_TCP, SO_TCP_TIME_WAIT_LEN, 4000));
  KEXPECT_GE(s1, 0);

  KEXPECT_EQ(3, vfs_write(c1, "abc", 3));
  KEXPECT_STREQ("abc", do_read(s1));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(c1));
  ksleep(10);

  // Reconnect to the same IP:port.  We should pick a new port to connect from
  // and not conflict with the server port that is still in TIME_WAIT.
  apos_ms_t start = get_time_ms();
  c1 = make_test_socket();
  KEXPECT_EQ(0, do_connect(c1, LO_DST_IP, SERVER_PORT));
  struct sockaddr_in c1_addr_2;
  KEXPECT_EQ(0, getsockname_inet(c1, &c1_addr_2));
  KEXPECT_EQ(c1_addr.sin_addr.s_addr, c1_addr_2.sin_addr.s_addr);
  KEXPECT_NE(c1_addr.sin_port, c1_addr_2.sin_port);

  int s2 = net_accept(server, NULL, NULL);
  KEXPECT_GE(s2, 0);
  apos_ms_t end = get_time_ms();
  KEXPECT_LT(end - start, 800);  // We should be able to connect() quickly.

  KEXPECT_EQ(3, vfs_write(c1, "123", 3));
  KEXPECT_STREQ("123", do_read(s2));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(c1));

  close_time_wait(s1);
  close_time_wait(s2);
  KEXPECT_EQ(0, vfs_close(server));
}

// Helpers for sockmap tests.
static void make_two_sin(const char* local, int local_port, const char* remote,
                         int remote_port, struct sockaddr_storage* local_sin,
                         struct sockaddr_storage* remote_sin) {
  make_saddr((struct sockaddr_storage_ip*)local_sin, local, local_port);
  if (remote) {
    make_saddr((struct sockaddr_storage_ip*)remote_sin, remote, remote_port);
  }
}

static socket_tcp_t* tcpsm_do_find(const tcp_sockmap_t* sm, const char* local,
                                   int local_port, const char* remote,
                                   int remote_port) {
  struct sockaddr_storage local_sin, remote_sin;
  make_two_sin(local, local_port, remote, remote_port, &local_sin, &remote_sin);
  return tcpsm_find(sm, &local_sin, remote ? &remote_sin : NULL);
}

static int tcpsm_do_bind2(tcp_sockmap_t* sm, const char* local, int local_port,
                          const char* remote, int remote_port,
                          int flags, socket_tcp_t* socket, char* local_out) {
  struct sockaddr_storage local_sin, remote_sin;
  make_two_sin(local, local_port, remote, remote_port, &local_sin, &remote_sin);
  int result =
      tcpsm_bind(sm, &local_sin, remote ? &remote_sin : NULL, flags, socket);
  if (result == 0) {
    sockaddr2str((const struct sockaddr*)&local_sin, sizeof(local_sin),
                 local_out);
  }
  return result;
}

static int tcpsm_do_bind(tcp_sockmap_t* sm, const char* local, int local_port,
                         const char* remote, int remote_port,
                         socket_tcp_t* socket, char* local_out) {
  return tcpsm_do_bind2(sm, local, local_port, remote, remote_port, 0, socket,
                        local_out);
}

static int tcpsm_do_remove(tcp_sockmap_t* sm, const char* local, int local_port,
                           const char* remote, int remote_port,
                           socket_tcp_t* socket) {
  struct sockaddr_storage local_sin, remote_sin;
  make_two_sin(local, local_port, remote, remote_port, &local_sin, &remote_sin);
  return tcpsm_remove(sm, &local_sin, remote ? &remote_sin : NULL, socket);
}

static void tcpsm_do_mark_reusable(tcp_sockmap_t* sm, const char* local,
                                   int local_port, const char* remote,
                                   int remote_port, socket_tcp_t* socket) {
  struct sockaddr_storage local_sin, remote_sin;
  make_two_sin(local, local_port, remote, remote_port, &local_sin, &remote_sin);
  tcpsm_mark_reusable(sm, &local_sin, &remote_sin, socket);
}

static void sockmap_find_tests(void) {
  KTEST_BEGIN("TCP: basic sockmap test");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET, 5, 7);
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));


  KTEST_BEGIN("TCP: sockmap 5-tuple lookup");
  socket_tcp_t s1, s2;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 90, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));


  KTEST_BEGIN("TCP: sockmap 3-tuple lookup");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 90, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.4", 90, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.5", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));


  KTEST_BEGIN("TCP: sockmap 3-tuple lookup (any-addr)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "5.6.7.8", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 90, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.4", 90, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.5", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));


  KTEST_BEGIN("TCP: sockmap 5-to-3 tuple fallback");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("1.2.3.4:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 80, "1.2.3.4", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 80, "1.2.3.4", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 90, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, "1.2.3.4", 80));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));

  tcpsm_cleanup(&sm);
}

static void sockmap_find_tests2(void) {
  KTEST_BEGIN("TCP: sockmap 5-to-3 tuple fallback (any-address)");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET, 5, 7);
  socket_tcp_t s1, s2, s3;
  char local[SOCKADDR_PRETTY_LEN];

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "5.6.7.8", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 90, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, "1.2.3.4", 80));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 91));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));


  KTEST_BEGIN("TCP: sockmap 5-to-3 tuple double fallback");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_STREQ("1.2.3.4:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s3, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "5.6.7.8", 80, NULL, 0));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 80));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "5.6.7.8", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, "1.2.3.4", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 90, "1.2.3.4", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "5.6.7.8", 90, "1.2.3.4", 80));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 91));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s3));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s1));

  tcpsm_cleanup(&sm);
}

static void sockmap_bind_tests(void) {
  KTEST_BEGIN("TCP: arg validation");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET, 5, 7);

  socket_tcp_t s1, s2;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "0.0.0.0", 90, &s1, local));
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 0, &s1, local));
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "0.0.0.0", 0, &s1, local));
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "0.0.0.0", 80, "5.6.7.8", 90, &s1, local));


  KTEST_BEGIN("TCP: bind 5-tuple collision");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));


  KTEST_BEGIN("TCP: bind 3-tuple collision");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  // A more specific 5-tuple binding should succeed.
  KEXPECT_EQ(0,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, NULL, 0));


  KTEST_BEGIN("TCP: bind 3-tuple any-addr collision");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:80", local);

  // A more specific 5-tuple binding should succeed.
  KEXPECT_EQ(0,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "1.2.3.4", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 80, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 80, NULL, 0));
  tcpsm_cleanup(&sm);
}

static void sockmap_bind_tests2(void) {
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET, 5, 7);

  socket_tcp_t s1, s2, s3, s4;
  char local[SOCKADDR_PRETTY_LEN];

  KTEST_BEGIN("TCP: port assignment");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:5", local);
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 5, NULL, 0, &s1, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 5, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 5, NULL, 0));


  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 6, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:6", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("0.0.0.0:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 7, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("0.0.0.0:5", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("0.0.0.0:7", local);
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s4, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s4, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 6, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 6, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("0.0.0.0:6", local);
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "0.0.0.0", 6, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 6, NULL, 0, &s1));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "0.0.0.0", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 5, NULL, 0, &s2));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "0.0.0.0", 7, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 7, NULL, 0, &s3));

  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 5, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 6, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 7, NULL, 0));


  KTEST_BEGIN("TCP: port assignment (cross-IP port reuse)");
  // Binding to specific IPs should allow port reuse.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("1.2.3.4:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 7, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("1.2.3.4:5", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "5.6.7.8", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("5.6.7.8:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "5.6.7.8", 6, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "5.6.7.8", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("5.6.7.8:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "5.6.7.8", 7, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "5.6.7.8", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("5.6.7.8:5", local);
  // ...but the any-IP should not be able to use port 5.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("0.0.0.0:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 6, NULL, 0, &s3));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("0.0.0.0:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 7, NULL, 0, &s3));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("0.0.0.0:6", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, NULL, 0, &s1));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "5.6.7.8", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "5.6.7.8", 5, NULL, 0, &s2));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "0.0.0.0", 6, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 6, NULL, 0, &s3));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "0.0.0.0", 5, NULL, 0));
  tcpsm_cleanup(&sm);
}

static void sockmap_bind_tests3(void) {
  tcp_sockmap_t sm;
  socket_tcp_t s1, s2, s3;
  char local[SOCKADDR_PRETTY_LEN];

  KTEST_BEGIN("TCP: port assignment (5-tuple)");
  tcpsm_init(&sm, AF_INET, 5, 7);
  // When the 5-tuple is bound first, 3-tuple binds should not be able to reuse
  // the same port.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s2, local));
  KEXPECT_STREQ("1.2.3.4:6", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("1.2.3.4:7", local);

  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 6, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 7, NULL, 0, &s3));

  // When the 3-tuple is bound first, 5-tuple binds can reuse the port (due to
  // the asymmetry of port conflicts).
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("1.2.3.4:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 6, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 7, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s2, local));
  KEXPECT_STREQ("1.2.3.4:6", local);

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 6, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, NULL, 0, &s3));

  // As above, but with the any-address.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("0.0.0.0:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 7, NULL, 0, &s3));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "0.0.0.0", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("0.0.0.0:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 6, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 7, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "1.2.3.4", 0, "5.6.7.8", 90, &s1, local));
  KEXPECT_STREQ("1.2.3.4:5", local);

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 5, NULL, 0, &s3));

  tcpsm_cleanup(&sm);
}

static void sockmap_reuseaddr_tests(void) {
  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with 5-tuple bind");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET, 5, 7);

  socket_tcp_t s1, s2, s3, s4;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                               TCPSM_REUSEADDR, &s1, local));
  KEXPECT_STREQ("1.2.3.4:80", local);

  // A 5-tuple conflict should always fail.
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90, 0, &s1, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s1, local));

  // As should 3-tuple conflicts.
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));

  // Mark the address as reusable then retest.
  tcpsm_do_mark_reusable(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s1);

  // All binds without TCPSM_REUSEADDR should still fail.
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90, 0, &s1, local));

  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, 0, &s2, local));

  // With the flag set, the 5-tuple should still fail, but both 3-tuple types
  // should succeed.
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s1, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with multiple bindings");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                               TCPSM_REUSEADDR, &s1, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 91,
                               TCPSM_REUSEADDR, &s3, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));

  // Mark the address as reusable then retest.
  tcpsm_do_mark_reusable(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2);

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 91,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));

  tcpsm_do_mark_reusable(&sm, "1.2.3.4", 80, "5.6.7.8", 91, &s3);

  // With both 5-tuples marked reusable, the any-addr should now succeed as it
  // won't conflict with either the explicit 3-tuple or the reusable 5-tuples.
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 91,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s4, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s4));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s1));

  // With the flag set, the 5-tuple should still fail, but both 3-tuple types
  // should succeed.
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 91,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s4, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s4));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s4, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s4));

  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 90));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "1.2.3.4", 80, "5.6.7.8", 91));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 91, &s3));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with 3-tuple binding");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                               TCPSM_REUSEADDR, &s1, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s2));

  // Create a 5-tuple as well and try again, for kicks.
  KEXPECT_EQ(0,
             tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90, 0, &s2, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));

  tcpsm_do_mark_reusable(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2);
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s3, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s3));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s1));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with 3-tuple binding (any-addr)");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                               TCPSM_REUSEADDR, &s1, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s2));

  // Create a 5-tuple as well and try again, for kicks.
  KEXPECT_EQ(0,
             tcpsm_do_bind2(&sm, "1.2.3.4", 80, "5.6.7.8", 90, 0, &s2, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));

  tcpsm_do_mark_reusable(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2);
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "0.0.0.0", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s3, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, NULL, 0, &s3));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 80, "5.6.7.8", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "0.0.0.0", 80, NULL, 0, &s1));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR doesn't affect port selection");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 5, "5.6.7.8", 90,
                               TCPSM_REUSEADDR, &s1, local));
  tcpsm_do_mark_reusable(&sm, "1.2.3.4", 5, "5.6.7.8", 90, &s1);

  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 0, "5.6.7.8", 91,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_STREQ("1.2.3.4:5", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, "5.6.7.8", 91, &s2));

  // We should not assign port 5 automatically.
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 0, NULL, 0,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_STREQ("1.2.3.4:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 6, NULL, 0, &s2));

  // ...but should be assignable explicitly.
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "1.2.3.4", 5, NULL, 0,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_STREQ("1.2.3.4:5", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, NULL, 0, &s2));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "1.2.3.4", 5, "5.6.7.8", 90, &s1));


  KTEST_BEGIN("TCP: invalid bind flags");
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind2(&sm, "1.2.3.4", 5, "5.6.7.8", 90, 20, &s1, local));

  tcpsm_cleanup(&sm);
}

static void sockmap_find_ipv6_tests(void) {
  KTEST_BEGIN("TCP: sockmap IPv6 basic setup ");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET6, 5, 7);
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::1", 90));


  KTEST_BEGIN("TCP: sockmap 5-tuple lookup (IPv6)");
  socket_tcp_t s1, s2;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:80", local);

  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::1", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 90, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, "::2", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));


  KTEST_BEGIN("TCP: sockmap 3-tuple lookup (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::1]:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 90, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::1", 90, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::3", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));


  KTEST_BEGIN("TCP: sockmap 3-tuple lookup (any-addr) (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::2", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 90, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::1", 90, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::3", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, "::2", 90, &s1));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));


  KTEST_BEGIN("TCP: sockmap 5-to-3 tuple fallback (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::1]:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_STREQ("[::1]:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 80, "::1", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 80, "::1", 90));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 90, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, "::1", 80));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, "::2", 90));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  tcpsm_cleanup(&sm);
}

static void sockmap_find_ipv6_tests2(void) {
  KTEST_BEGIN("TCP: sockmap 5-to-3 tuple fallback (any-address) (IPv6)");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET6, 5, 7);
  socket_tcp_t s1, s2, s3;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_STREQ("[::1]:80", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::2", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 90, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, "::1", 80));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 91));

  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(-ENOENT, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));


  KTEST_BEGIN("TCP: sockmap 5-to-3 tuple double fallback (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_STREQ("[::1]:80", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s3, local));
  KEXPECT_STREQ("[::1]:80", local);

  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, NULL, 0));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::2", 80, NULL, 0));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, "::1", 80));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::2", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, "::1", 90));
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 90, "::1", 80));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::2", 90, "::1", 80));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, "::2", 91));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s3));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s1));


  KTEST_BEGIN("TCP: sockmap allocates port (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::1]:5", local);
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 0, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_STREQ("[::1]:6", local);
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 0, NULL, 0, TCPSM_REUSEADDR,
                               &s3, local));
  KEXPECT_STREQ("[::1]:7", local);
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 0, NULL, 0,
                                          TCPSM_REUSEADDR, &s1, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 6, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 7, NULL, 0, &s3));

  tcpsm_cleanup(&sm);
}

static void sockmap_bind_ipv6_tests(void) {
  KTEST_BEGIN("TCP: arg validation");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET6, 5, 7);

  socket_tcp_t s1, s2;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "::1", 80, "::", 90, &s1, local));
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "::1", 80, "::2", 0, &s1, local));
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "::1", 80, "::", 0, &s1, local));
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind(&sm, "::", 80, "::2", 90, &s1, local));


  KTEST_BEGIN("TCP: bind 5-tuple collision");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:80", local);

  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));


  KTEST_BEGIN("TCP: bind 3-tuple collision");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::1]:80", local);

  // A more specific 5-tuple binding should succeed.
  KEXPECT_EQ(0,
             tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, NULL, 0));


  KTEST_BEGIN("TCP: bind 3-tuple any-addr collision");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:80", local);

  // A more specific 5-tuple binding should succeed.
  KEXPECT_EQ(0,
             tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, "::2", 90, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::1", 80, NULL, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 80, NULL, 0, &s2, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 80, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 80, NULL, 0));
  tcpsm_cleanup(&sm);
}

static void sockmap_bind_ipv6_tests2(void) {
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET6, 5, 7);

  socket_tcp_t s1, s2, s3, s4;
  char local[SOCKADDR_PRETTY_LEN];

  KTEST_BEGIN("TCP: port assignment (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:5", local);
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 5, NULL, 0, &s1, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 5, NULL, 0, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 5, NULL, 0));


  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 6, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:6", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("[::]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 7, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("[::]:5", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::]:7", local);
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s4, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s4, local));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 6, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 6, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::]:6", local);
  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::", 6, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 6, NULL, 0, &s1));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 5, NULL, 0, &s2));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "::", 7, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 7, NULL, 0, &s3));

  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 5, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 6, NULL, 0));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 7, NULL, 0));


  KTEST_BEGIN("TCP: port assignment (cross-IP port reuse) (IPv6)");
  // Binding to specific IPs should allow port reuse.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::1]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 7, NULL, 0, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, NULL, 0, &s1, local));
  KEXPECT_STREQ("[::1]:5", local);
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::2", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("[::2]:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::2", 6, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::2", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("[::2]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::2", 7, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::2", 0, NULL, 0, &s2, local));
  KEXPECT_STREQ("[::2]:5", local);
  // ...but the any-IP should not be able to use port 5.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::]:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 6, NULL, 0, &s3));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 7, NULL, 0, &s3));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::]:6", local);

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, NULL, 0, &s1));
  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::2", 5, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::2", 5, NULL, 0, &s2));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "::", 6, NULL, 0));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 6, NULL, 0, &s3));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::", 5, NULL, 0));
  tcpsm_cleanup(&sm);
}

static void sockmap_bind_ipv6_tests3(void) {
  tcp_sockmap_t sm;
  socket_tcp_t s1, s2, s3;
  char local[SOCKADDR_PRETTY_LEN];

  KTEST_BEGIN("TCP: port assignment (5-tuple) (IPv6)");
  tcpsm_init(&sm, AF_INET6, 5, 7);
  // When the 5-tuple is bound first, 3-tuple binds should not be able to reuse
  // the same port.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s2, local));
  KEXPECT_STREQ("[::1]:6", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::1]:7", local);

  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 6, "::2", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 7, NULL, 0, &s3));

  // When the 3-tuple is bound first, 5-tuple binds can reuse the port (due to
  // the asymmetry of port conflicts).
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::1]:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 6, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 7, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s2, local));
  KEXPECT_STREQ("[::1]:6", local);

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 6, "::2", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, NULL, 0, &s3));

  // As above, but with the any-address.
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 7, NULL, 0, &s3));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::", 0, NULL, 0, &s3, local));
  KEXPECT_STREQ("[::]:5", local);

  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 6, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:7", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 7, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_bind(&sm, "::1", 0, "::2", 90, &s1, local));
  KEXPECT_STREQ("[::1]:5", local);

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, "::2", 90, &s1));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 5, NULL, 0, &s3));

  tcpsm_cleanup(&sm);
}

static void sockmap_reuseaddr_ipv6_tests(void) {
  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with 5-tuple bind (IPv6)");
  tcp_sockmap_t sm;
  tcpsm_init(&sm, AF_INET6, 5, 7);

  socket_tcp_t s1, s2, s3, s4;
  char local[SOCKADDR_PRETTY_LEN];
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                               TCPSM_REUSEADDR, &s1, local));
  KEXPECT_STREQ("[::1]:80", local);

  // A 5-tuple conflict should always fail.
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "::1", 80, "::2", 90, 0, &s1, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s1, local));

  // As should 3-tuple conflicts.
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "::", 80, NULL, 0, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));

  // Mark the address as reusable then retest.
  tcpsm_do_mark_reusable(&sm, "::1", 80, "::2", 90, &s1);

  // All binds without TCPSM_REUSEADDR should still fail.
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "::1", 80, "::2", 90, 0, &s1, local));

  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, 0, &s2, local));
  KEXPECT_EQ(-EADDRINUSE,
             tcpsm_do_bind2(&sm, "::", 80, NULL, 0, 0, &s2, local));

  // With the flag set, the 5-tuple should still fail, but both 3-tuple types
  // should succeed.
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s1, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s2));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));

  KEXPECT_EQ(&s1, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s1));
  KEXPECT_EQ(NULL, tcpsm_do_find(&sm, "::1", 80, "::2", 90));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with multiple bindings (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                               TCPSM_REUSEADDR, &s1, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, "::2", 91,
                               TCPSM_REUSEADDR, &s3, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));

  // Mark the address as reusable then retest.
  tcpsm_do_mark_reusable(&sm, "::1", 80, "::2", 90, &s2);

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 91,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));

  tcpsm_do_mark_reusable(&sm, "::1", 80, "::2", 91, &s3);

  // With both 5-tuples marked reusable, the any-addr should now succeed as it
  // won't conflict with either the explicit 3-tuple or the reusable 5-tuples.
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 91,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s4, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s4));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s1));

  // With the flag set, the 5-tuple should still fail, but both 3-tuple types
  // should succeed.
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 90,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, "::2", 91,
                                         TCPSM_REUSEADDR, &s4, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s4, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s4));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s4, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s4));

  KEXPECT_EQ(&s2, tcpsm_do_find(&sm, "::1", 80, "::2", 90));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(&s3, tcpsm_do_find(&sm, "::1", 80, "::2", 91));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 91, &s3));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with 3-tuple binding (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                               TCPSM_REUSEADDR, &s1, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s2));

  // Create a 5-tuple as well and try again, for kicks.
  KEXPECT_EQ(0,
             tcpsm_do_bind2(&sm, "::1", 80, "::2", 90, 0, &s2, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));

  tcpsm_do_mark_reusable(&sm, "::1", 80, "::2", 90, &s2);
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s3, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s3));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s1));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR with 3-tuple binding (any-addr) (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                               TCPSM_REUSEADDR, &s1, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s2, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s2, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s2));

  // Create a 5-tuple as well and try again, for kicks.
  KEXPECT_EQ(0,
             tcpsm_do_bind2(&sm, "::1", 80, "::2", 90, 0, &s2, local));

  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));

  tcpsm_do_mark_reusable(&sm, "::1", 80, "::2", 90, &s2);
  KEXPECT_EQ(-EADDRINUSE, tcpsm_do_bind2(&sm, "::", 80, NULL, 0,
                                         TCPSM_REUSEADDR, &s3, local));
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 80, NULL, 0, TCPSM_REUSEADDR,
                               &s3, local));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, NULL, 0, &s3));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 80, "::2", 90, &s2));
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::", 80, NULL, 0, &s1));


  KTEST_BEGIN("TCP: TCPSM_REUSEADDR doesn't affect port selection (IPv6)");
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 5, "::2", 90,
                               TCPSM_REUSEADDR, &s1, local));
  tcpsm_do_mark_reusable(&sm, "::1", 5, "::2", 90, &s1);

  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 0, "::2", 91,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_STREQ("[::1]:5", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, "::2", 91, &s2));

  // We should not assign port 5 automatically.
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 0, NULL, 0,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_STREQ("[::1]:6", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 6, NULL, 0, &s2));

  // ...but should be assignable explicitly.
  KEXPECT_EQ(0, tcpsm_do_bind2(&sm, "::1", 5, NULL, 0,
                               TCPSM_REUSEADDR, &s2, local));
  KEXPECT_STREQ("[::1]:5", local);
  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, NULL, 0, &s2));

  KEXPECT_EQ(0, tcpsm_do_remove(&sm, "::1", 5, "::2", 90, &s1));


  KTEST_BEGIN("TCP: invalid bind flags (IPv6)");
  KEXPECT_EQ(-EINVAL,
             tcpsm_do_bind2(&sm, "::1", 5, "::2", 90, 20, &s1, local));

  tcpsm_cleanup(&sm);
}

static void sockmap_tests(void) {
  sockmap_find_tests();
  sockmap_find_tests2();
  sockmap_bind_tests();
  sockmap_bind_tests2();
  sockmap_bind_tests3();
  sockmap_reuseaddr_tests();
  sockmap_find_ipv6_tests();
  sockmap_find_ipv6_tests2();
  sockmap_bind_ipv6_tests();
  sockmap_bind_ipv6_tests2();
  sockmap_bind_ipv6_tests3();
  sockmap_reuseaddr_ipv6_tests();
}

static void basic_ipv6_test(void) {
  KTEST_BEGIN("TCP: listen() basic test (IPv6)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);

  // Should not be able to listen on an unbound socket.
  KEXPECT_EQ(-EDESTADDRREQ, net_listen(s.socket, 10));

  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, "1.2.3.4", 0x1234));
  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, SRC_IP, 0x1234));
  KEXPECT_EQ(-EAFNOSUPPORT, do_bind(s.socket, "0.0.0.0", 0x1234));

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));

  KEXPECT_EQ(0, net_listen(s.socket, 10));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_EQ(-EINVAL, net_listen(s.socket, 10));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RDWR));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));

  // Should not be able to call connect() on a listening socket.
  KEXPECT_EQ(-EOPNOTSUPP, do_connect(s.socket, "2001:db8::2", 0x5678));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // Or read/write.
  char buf;
  KEXPECT_EQ(-ENOTCONN, vfs_read(s.socket, &buf, 1));
  KEXPECT_EQ(-ENOTCONN, vfs_write(s.socket, &buf, 1));

  KEXPECT_STREQ("[2001:db8::1]:4660", getsockname_str(s.socket));
  KEXPECT_STREQ("ENOTCONN", getpeername_str(s.socket));

  // Any packet other than a SYN should get a RST or be ignored.
  SEND_PKT(&s, RST_PKT(/* seq */ 500, /* ack */ 101));
  KEXPECT_FALSE(raw_has_packets(&s));

  SEND_PKT(&s, ACK_PKT(/* seq */ 500, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 5000));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, DATA_PKT(/* seq */ 500, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, DATA_FIN_PKT(/* seq */ 500, /* ack */ 101, "abc"));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));
  SEND_PKT(&s, FIN_PKT(/* seq */ 500, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  // Try some mutants that don't have the ACK bit set for fun.
  SEND_PKT(&s, NOACK(DATA_PKT(/* seq */ 500, /* ack */ 101, "abc")));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 503));
  SEND_PKT(&s, NOACK(DATA_FIN_PKT(/* seq */ 500, /* ack */ 101, "abc")));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 504));
  SEND_PKT(&s, NOACK(FIN_PKT(/* seq */ 500, /* ack */ 101)));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 501));

  // A SYN (or SYN-ACK) with data should also be rejected.
  test_packet_spec_t p = DATA_PKT(/* seq */ 500, /* ack */ 101, "abc");
  p.flags = TCP_FLAG_SYN;
  SEND_PKT(&s, p);
  EXPECT_PKT(&s, RST_PKT(/* seq */ 0, /* ack */ 504));
  p.flags |= TCP_FLAG_ACK;
  SEND_PKT(&s, p);
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  // Send a SYN, complete the connection.
  tcp_test_state_t c1;
  init_tcp_test_child(&s, &c1, "2001:db8::2", 2000);
  c1.flow_label = 966464;
  SEND_PKT(&c1, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c1,
             SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));

  // We should be able to accept() a child socket.
  char addr[SOCKADDR_PRETTY_LEN];
  c1.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c1.socket, 0);
  KEXPECT_STREQ("[2001:db8::2]:2000", addr);
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // listen(), accept(), etc should not work on the child socket.
  KEXPECT_EQ(-EINVAL, net_listen(c1.socket, 10));
  KEXPECT_EQ(-EINVAL, do_accept(c1.socket, addr));
  KEXPECT_EQ(-EINVAL, net_accept_queue_length(c1.socket));

  // Do a second connection.
  tcp_test_state_t c2;
  init_tcp_test_child(&s, &c2, "2001:db8::3", 600);
  c2.flow_label = 54956;
  SEND_PKT(&c2, SYN_PKT(/* seq */ 500, /* wndsize */ 8000));
  EXPECT_PKT(&c2,
             SYNACK_PKT(/* seq */ 100, /* ack */ 501, /* wndsize */ 16384));
  SEND_PKT(&c2, ACK_PKT(/* seq */ 501, /* ack */ 101));
  KEXPECT_EQ(1, net_accept_queue_length(s.socket));
  c2.socket = do_accept(s.socket, addr);
  KEXPECT_GE(c2.socket, 0);
  KEXPECT_STREQ("[2001:db8::3]:600", addr);
  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));
  KEXPECT_STREQ("ESTABLISHED", get_sock_state(c1.socket));
  KEXPECT_EQ(0, net_accept_queue_length(s.socket));

  // Should be able to pass data on both sockets.
  SEND_PKT(&c1, DATA_PKT(/* seq */ 501, /* ack */ 101, "abc"));
  SEND_PKT(&c2, DATA_PKT(/* seq */ 501, /* ack */ 101, "123"));
  EXPECT_PKT(&c1, ACK_PKT(/* seq */ 101, /* ack */ 504));
  EXPECT_PKT(&c2, ACK_PKT(/* seq */ 101, /* ack */ 504));

  KEXPECT_STREQ("abc", do_read(c1.socket));
  KEXPECT_STREQ("123", do_read(c2.socket));

  KEXPECT_EQ(5, vfs_write(c1.socket, "ABCDE", 5));
  KEXPECT_EQ(5, vfs_write(c2.socket, "67890", 5));
  EXPECT_PKT(&c1, DATA_PKT(/* seq */ 101, /* ack */ 504, "ABCDE"));
  EXPECT_PKT(&c2, DATA_PKT(/* seq */ 101, /* ack */ 504, "67890"));
  SEND_PKT(&c1, ACK_PKT(/* seq */ 504, /* ack */ 106));
  SEND_PKT(&c2, ACK_PKT(/* seq */ 504, /* ack */ 106));

  KEXPECT_TRUE(do_standard_finish(&c1, 5, 3));
  KEXPECT_TRUE(do_standard_finish(&c2, 5, 3));

  KEXPECT_STREQ("CLOSED_DONE", get_sock_state(c1.socket));
  KEXPECT_EQ(-EINVAL, net_listen(c1.socket, 10));

  KEXPECT_STREQ("LISTEN", get_sock_state(s.socket));

  cleanup_tcp_test(&s);
  cleanup_tcp_test(&c1);
  cleanup_tcp_test(&c2);
}

static void basic_ipv6_connect_test(void) {
  KTEST_BEGIN("TCP: basic connect() (IPv6)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);
  s.flow_label = 473694;

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "2001:db8::2", 0x5678));

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

static void basic_ipv6_connect_reset_test(void) {
  KTEST_BEGIN("TCP: basic connect() then reset (IPv6)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);
  s.flow_label = 473694;

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));

  KEXPECT_TRUE(start_connect(&s, "2001:db8::2", 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));

  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  // Shut down the connect then trigger a reset.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_RD));

  SEND_PKT(&s, DATA_PKT(/* seq */ 501, /* ack */ 101, "xyz"));
  EXPECT_PKT(&s, RST_PKT(/* seq */ 101, /* ack */ 501));
  s.flow_label = FLOW_LABEL_ZERO;
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 101));
  EXPECT_PKT(&s, RST_NOACK_PKT(/* seq */ 101));

  char buf[10];
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));
  KEXPECT_EQ(0, vfs_read(s.socket, buf, 10));

  KEXPECT_EQ(-ENOTCONN, net_shutdown(s.socket, SHUT_RD));

  KEXPECT_EQ(-EPIPE, vfs_write(s.socket, "abc", 3));
  KEXPECT_TRUE(has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  cleanup_tcp_test(&s);
}

static void tcp_ipv6_self_connect_test(void) {
  KTEST_BEGIN("TCP: IPv6 basic loopback self-connect test");
  int s1 = net_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(s1, 0);
  int s2 = net_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(s2, 0);

  struct sockaddr_in6 dst;
  KEXPECT_EQ(0, str2sin6("::1", 1234, &dst));
  KEXPECT_EQ(0, net_bind(s2, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_EQ(0, net_listen(s2, 10));
  KEXPECT_EQ(0, net_connect(s1, (struct sockaddr*)&dst, sizeof(dst)));

  struct sockaddr_storage src;
  KEXPECT_EQ(sizeof(struct sockaddr_in6), net_getsockname(s1, &src));
  char str[SOCKADDR_PRETTY_LEN];
  ksprintf(str, "[::1]:%d", get_sockaddrs_port(&src));
  KEXPECT_STREQ(str, sas2str(&src));

  struct sockaddr_storage peer;
  socklen_t peer_len = sizeof(peer);
  int s3 = net_accept(s2, (struct sockaddr*)&peer, &peer_len);
  KEXPECT_GE(s3, 0);
  KEXPECT_EQ(sizeof(struct sockaddr_in6), peer_len);
  KEXPECT_STREQ(str, sas2str(&peer));

  KEXPECT_EQ(3, vfs_write(s1, "abc", 3));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s3, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  KEXPECT_EQ(3, vfs_write(s3, "def", 3));
  KEXPECT_EQ(3, vfs_read(s1, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("def", buf);

  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(0, net_shutdown(s3, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  close_time_wait(s3);
}

static void tcp_ipv6_bind_port_only_test(void) {
  KTEST_BEGIN("TCP: IPv6 port-only bind test");
  int s1 = net_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(s1, 0);
  int s2 = net_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  KEXPECT_GE(s2, 0);

  struct sockaddr_in6 dst;
  KEXPECT_EQ(0, str2sin6("::", 1234, &dst));
  KEXPECT_EQ(0, net_bind(s2, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_EQ(0, net_listen(s2, 10));

  struct sockaddr_storage src;
  KEXPECT_EQ(sizeof(struct sockaddr_in6), net_getsockname(s2, &src));
  KEXPECT_STREQ("[::]:1234", sas2str(&src));

  KEXPECT_EQ(0, str2sin6("::", 5678, &dst));
  KEXPECT_EQ(0, net_bind(s1, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_EQ(sizeof(struct sockaddr_in6), net_getsockname(s1, &src));
  KEXPECT_STREQ("[::]:5678", sas2str(&src));
  KEXPECT_EQ(0, str2sin6("::1", 1234, &dst));
  KEXPECT_EQ(0, net_connect(s1, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_EQ(sizeof(struct sockaddr_in6), net_getsockname(s1, &src));
  KEXPECT_STREQ("[::1]:5678", sas2str(&src));

  struct sockaddr_storage peer;
  socklen_t peer_len = sizeof(peer);
  int s3 = net_accept(s2, (struct sockaddr*)&peer, &peer_len);
  KEXPECT_GE(s3, 0);
  KEXPECT_EQ(sizeof(struct sockaddr_in6), peer_len);
  KEXPECT_STREQ("[::1]:5678", sas2str(&peer));

  KEXPECT_EQ(3, vfs_write(s1, "abc", 3));
  char buf[10];
  KEXPECT_EQ(3, vfs_read(s3, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);

  KEXPECT_EQ(3, vfs_write(s3, "def", 3));
  KEXPECT_EQ(3, vfs_read(s1, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("def", buf);

  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(0, net_shutdown(s3, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  close_time_wait(s3);
}

static void bad_ipv6_packet_test(void) {
  KTEST_BEGIN("TCP: bad IPv6 packet (truncated TCP header)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "2001:db8::2", 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 0));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Send back a truncated SYN/ACK.
  pbuf_t* pkt = build_pkt(
      &s, SYNACK_PKT(/* seq */ 500, /* seq */ 101, /* wndsize */ 16000));
  pbuf_trim_end(pkt, 1);
  KEXPECT_TRUE(send_pkt(&s, pkt));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void bad_ipv6_packet_test2(void) {
  KTEST_BEGIN("TCP: bad IPv6 packet (header size too small)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "2001:db8::2", 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 0));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Send back a SYN/ACK with a too-small header size.
  pbuf_t* pkt = build_pkt(
      &s, SYNACK_PKT(/* seq */ 500, /* seq */ 101, /* wndsize */ 16000));
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pkt);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  tcp_hdr->data_offset = 4;
  calc_checksum(&s, pkt);
  KEXPECT_TRUE(send_pkt(&s, pkt));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void bad_ipv6_packet_test3(void) {
  KTEST_BEGIN("TCP: bad IPv6 packet (header size too large)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "2001:db8::2", 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 0));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Send back a SYN/ACK with a too-small header size.
  pbuf_t* pkt = build_pkt(
      &s, SYNACK_PKT(/* seq */ 500, /* seq */ 101, /* wndsize */ 16000));
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pkt);
  KEXPECT_EQ(5, tcp_hdr->data_offset);
  tcp_hdr->data_offset = 6;
  calc_checksum(&s, pkt);
  KEXPECT_TRUE(send_pkt(&s, pkt));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void bad_ipv6_packet_test4(void) {
  KTEST_BEGIN("TCP: bad IPv6 packet (bad checksum)");
  tcp_test_state_t s;
  init_tcp_test(&s, "2001:db8::1", 0x1234, "2001:db8::2", 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, "2001:db8::1", 0x1234));
  KEXPECT_TRUE(start_connect(&s, "2001:db8::2", 0x5678));
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 0));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  // Send back a SYN/ACK with a too-small header size.
  pbuf_t* pkt = build_pkt(
      &s, SYNACK_PKT(/* seq */ 500, /* seq */ 101, /* wndsize */ 16000));
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pbuf_get(pkt);
  tcp_hdr->checksum = 1234;
  KEXPECT_TRUE(send_pkt(&s, pkt));
  KEXPECT_STREQ("SYN_SENT", get_sock_state(s.socket));

  KEXPECT_FALSE(ntfn_await_with_timeout(&s.op.done, BLOCK_VERIFY_MS));
  proc_kill_thread(s.op.thread, SIGUSR1);
  KEXPECT_EQ(-EINTR, finish_op(&s));
  KEXPECT_FALSE(raw_has_packets(&s));

  cleanup_tcp_test(&s);
}

static void tcp_ipv6_tests(void) {
  basic_ipv6_test();
  basic_ipv6_connect_test();
  basic_ipv6_connect_reset_test();
  tcp_ipv6_self_connect_test();
  tcp_ipv6_bind_port_only_test();
  bad_ipv6_packet_test();
  bad_ipv6_packet_test2();
  bad_ipv6_packet_test3();
  bad_ipv6_packet_test4();
}

static void zwp_test1(void) {
  KTEST_BEGIN("TCP: zero-window probes sent (ZWP is a FIN)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_LT(get_rto(s.socket), 2000);

  set_rto(s.socket, 40);
  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  KEXPECT_EQ(1, vfs_write(s.socket, "6", 1));
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a series of ZWPs.
  ksleep(10);
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_TRUE(raw_has_packets_wait(&s, 200));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "6"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 107, /* wndsize */ WNDSIZE_ZERO));

  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_TRUE(raw_has_packets_wait(&s, 200));
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 107, /* ack */ 501));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 108));

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 108));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 108, /* ack */ 502));

  kill_time_wait(s.socket);
  cleanup_tcp_test(&s);
}

static void zwp_test2(void) {
  KTEST_BEGIN("TCP: zero-window probes sent (timer-based)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_LT(get_rto(s.socket), 2000);

  set_rto(s.socket, 20);
  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  KEXPECT_EQ(5, vfs_write(s.socket, "67890", 5));
  ksleep(100);

  // We should have gotten at least two ZWPs (one probe, one retransmit).
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "6"));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "6"));
  KEXPECT_LT(get_rto(s.socket), 1000);
  set_rto(s.socket, 1000);
  KEXPECT_LT(raw_drain_packets(&s), 4);

  // Send FIN to start connection close.
  SEND_PKT(&s, FIN_PKT(/* seq */ 501, /* ack */ 107));

  // Should get an ACK (with data).
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 107, /* ack */ 502, "7890"));
  KEXPECT_FALSE(raw_has_packets(&s));

  // Shutdown the connection from this side.
  KEXPECT_EQ(0, net_shutdown(s.socket, SHUT_WR));

  // Should get a FIN.
  EXPECT_PKT(&s, FIN_PKT(/* seq */ 111, /* ack */ 502));
  SEND_PKT(&s, ACK_PKT(502, /* ack */ 112));

  cleanup_tcp_test(&s);
}

static void open_window_test_hook(const char* name, int count, void* arg) {
  if (count != 0) return;
  tcp_test_state_t* s = (tcp_test_state_t*)arg;
  SEND_PKT(s, ACK_PKT(/* seq */ 501, /* ack */ 106));
  // TODO(SMP): reenable this when it's possible for this write race to happen
  // --- either due to a preemption during defint handling, or due to SMP.  This
  // verifies that we don't lose the write() call even though the window was
  // closed.  This can't currently run because we can't do a FD lookup from a
  // defint.
  // KEXPECT_EQ(2, vfs_write(s->socket, "ab", 2));
}

static void zwp_test3(void) {
  KTEST_BEGIN("TCP: zero-window probe races with window update");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.
  KEXPECT_LT(get_rto(s.socket), 2000);

  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));

  set_rto(s.socket, 40);
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  KEXPECT_EQ(3, vfs_write(s.socket, "678", 3));
  KEXPECT_FALSE(raw_has_packets(&s));
  test_point_add("tcp:send_datafin", open_window_test_hook, &s);

  // We should get the full message once the RTO timer expires.
  KEXPECT_TRUE(raw_has_packets_wait(&s, 200));
  KEXPECT_LE(1, test_point_remove("tcp:send_datafin"));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "678"));
  KEXPECT_EQ(2, vfs_write(s.socket, "ab", 2));  // TODO(SMP): see above.

  // We should also get the 'ab' sent right after the window opened.
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 109, /* ack */ 501, "ab"));

  // We should be able to send more.
  KEXPECT_EQ(2, vfs_write(s.socket, "90", 2));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 111, /* ack */ 501, "90"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 113));

  KEXPECT_TRUE(do_standard_finish(&s, 12, 0));
  cleanup_tcp_test(&s);
}

// Tests when the window is closed to zero spontaneously, not while ACK'ing any
// outstanding data.
static void zwp_test4(void) {
  KTEST_BEGIN("TCP: zero-window probes sent (window is spontaneously closed)");
  tcp_test_state_t s;
  init_tcp_test(&s, SRC_IP, 0x1234, DST_IP, 0x5678);

  KEXPECT_EQ(0, do_bind(s.socket, SRC_IP, 0x1234));

  KEXPECT_TRUE(start_connect(&s, DST_IP, 0x5678));

  // Do SYN, SYN-ACK, ACK.
  EXPECT_PKT(&s, SYN_PKT(/* seq */ 100, /* wndsize */ 16384));
  SEND_PKT(&s, SYNACK_PKT(/* seq */ 500, /* ack */ 101, /* wndsize */ 8000));
  EXPECT_PKT(&s, ACK_PKT(/* seq */ 101, /* ack */ 501));
  KEXPECT_EQ(0, finish_op(&s));  // connect() should complete successfully.

  set_rto(s.socket, 40);
  KEXPECT_EQ(5, vfs_write(s.socket, "12345", 5));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 101, /* ack */ 501, "12345"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 106));

  // _now_ close the window.
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 106, /* wndsize */ WNDSIZE_ZERO));

  KEXPECT_EQ(2, vfs_write(s.socket, "67", 2));

  // Should get a series of ZWPs.
  ksleep(10);
  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_TRUE(raw_has_packets_wait(&s, 200));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 106, /* ack */ 501, "6"));
  SEND_PKT(&s,
           ACK_PKT2(/* seq */ 501, /* ack */ 107, /* wndsize */ WNDSIZE_ZERO));

  KEXPECT_FALSE(raw_has_packets(&s));
  KEXPECT_TRUE(raw_has_packets_wait(&s, 200));
  EXPECT_PKT(&s, DATA_PKT(/* seq */ 107, /* ack */ 501, "7"));
  SEND_PKT(&s, ACK_PKT(/* seq */ 501, /* ack */ 108));

  KEXPECT_TRUE(do_standard_finish(&s, 7, 0));
  cleanup_tcp_test(&s);
}

static void zero_window_probe_tests(void) {
  zwp_test1();
  zwp_test2();
  zwp_test3();
  zwp_test4();
}

typedef struct {
  int server_fd;
  struct sockaddr_storage_ip server_addr;
} mt_test_args_t;

// Each server thread waits for a connection then echoes back what it gets.
static void* mt_server(void* arg) {
  sched_enable_preemption_for_test();
  mt_test_args_t* args = (mt_test_args_t*)arg;
  while (true) {
    int sock = net_accept(args->server_fd, NULL, NULL);
    if (sock < 0) {
      KEXPECT_EQ(-EINTR, sock);
      sched_disable_preemption();
      return NULL;
    }
    KEXPECT_EQ(0, set_rto(sock, 50));

    char buf[300];
    while (true) {
      int bytes = vfs_read(sock, buf, 300);
      KEXPECT_GE(bytes, 0);
      if (bytes == 0) {
        KEXPECT_EQ(0, vfs_close(sock));
        break;
      }
      int result = vfs_write(sock, buf, min(bytes, 100));
      KEXPECT_GE(result, 0);
      if (result < bytes) {
        int result2 = vfs_write(sock, buf + result, bytes - result);
        KEXPECT_GE(result2, 0);
        KEXPECT_EQ(bytes, result + result2);
      }
    }
  }
}

typedef struct {
  int sock;
  int bytes_read;
  uint32_t hash;
} mt_client_reader_args;

// A helper thread for the client that reads and calculates a hash.
static void* mt_client_reader(void* arg) {
  mt_client_reader_args* args = (mt_client_reader_args*)arg;

  const int kChunkSize = 999;
  char buf[kChunkSize];
  args->hash = fnv_hash_array_start();
  args->bytes_read = 0;
  while (true) {
    int bytes = vfs_read(args->sock, buf, kChunkSize);
    KEXPECT_GE(bytes, 0);
    if (bytes <= 0) {
      break;
    }
    args->hash = fnv_hash_array_continue(args->hash, buf, bytes);
    args->bytes_read += bytes;
  }
  sched_disable_preemption();
  return NULL;
}

// Each client thread repeatedly connects and sends data.
static void* mt_client(void* arg) {
  sched_enable_preemption_for_test();
  mt_test_args_t* args = (mt_test_args_t*)arg;
  const char* const data = kHamlet;
  const size_t data_len = kHamletSize;

  for (int i = 0; i < MT_CONNECT_ROUNDS; ++i) {
    int sock =
        net_socket(args->server_addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
    KEXPECT_GE(sock, 0);
    if (sock < 0) break;

    KEXPECT_EQ(0, do_setsockopt_int(sock, SOL_SOCKET, SO_RCVBUF, 1000));
    KEXPECT_EQ(0, do_setsockopt_int(sock, SOL_SOCKET, SO_SNDBUF, 1000));
    KEXPECT_EQ(0, set_rto(sock, 50));
    int result = net_connect(sock, (const struct sockaddr*)&args->server_addr,
                             sizeof(args->server_addr));
    KEXPECT_EQ(result, 0);
    if (result != 0) {
      KEXPECT_EQ(0, vfs_close(sock));
      continue;
    }

    kthread_t reader;
    mt_client_reader_args reader_args;
    reader_args.sock = sock;
    KEXPECT_EQ(0, proc_thread_create(&reader, mt_client_reader, &reader_args));

    uint32_t hash = fnv_hash_array_start();
    for (int j = 0; j < MT_WRITE_ROUNDS; ++j) {
      const char* buf = data;
      int bytes = data_len;
      int chunk_size = 123;
      while (bytes > 0) {
        int result = vfs_write(sock, buf, min(bytes, chunk_size));
        KEXPECT_GT(result, 0);
        if (result <= 0) {
          KEXPECT_EQ(0, vfs_close(sock));
          goto end;
        }
        hash = fnv_hash_array_continue(hash, buf, result);
        chunk_size = chunk_size * 2;
        if (chunk_size > 2000) chunk_size = 123;
        bytes -= result;
        buf += result;
      }
    }

    // Should trigger a FIN, then the server will also close it, and then the
    // reader will terminate.
    KEXPECT_EQ(0, net_shutdown(sock, SHUT_WR));
    KEXPECT_EQ(NULL, kthread_join(reader));
    KEXPECT_EQ(MT_WRITE_ROUNDS * data_len, reader_args.bytes_read);
    KEXPECT_EQ(hash, reader_args.hash);
    close_time_wait(sock);
  }

end:
  sched_disable_preemption();
  return NULL;
}

static void do_multithread_test(const char* addr, int port) {
  // First set up the server socket.
  mt_test_args_t args;
  make_saddr(&args.server_addr, addr, port);
  args.server_fd =
      net_socket(args.server_addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (!KEXPECT_GE(args.server_fd, 0)) {
    return;
  }

  if (!KEXPECT_EQ(
          0, net_bind(args.server_fd, (const struct sockaddr*)&args.server_addr,
                      sizeof(args.server_addr)))) {
    return;
  }

  if (!KEXPECT_EQ(0, net_listen(args.server_fd, 50))) {
    return;
  }

  // New create all our threads.
  kthread_t server_threads[MT_TEST_READERS];
  kthread_t client_threads[MT_TEST_WRITERS];
  for (int i = 0; i < MT_TEST_READERS; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&server_threads[i], &mt_server, &args));
  }
  for (int i = 0; i < MT_TEST_WRITERS; ++i) {
    KEXPECT_EQ(0, proc_thread_create(&client_threads[i], &mt_client, &args));
  }
  for (int i = 0; i < MT_TEST_WRITERS; ++i) {
    KEXPECT_EQ(NULL, kthread_join(client_threads[i]));
  }
  for (int i = 0; i < MT_TEST_READERS; ++i) {
    KEXPECT_EQ(0, proc_kill_thread(server_threads[i], SIGUSR1));
    KEXPECT_EQ(NULL, kthread_join(server_threads[i]));
  }
  KEXPECT_EQ(0, vfs_close(args.server_fd));
}

static void multithread_test(void) {
  KTEST_BEGIN("TCP: multithreaded test (IPv4)");
  do_multithread_test("127.0.0.1", MT_PORT);

  KTEST_BEGIN("TCP: multithreaded test (IPv6)");
  do_multithread_test("0::1", MT_PORT);
}

void tcp_test(void) {
  KTEST_SUITE_BEGIN("TCP");
  const int initial_cache_size = vfs_cache_size();
  const int initial_sockets = tcp_num_connected_sockets();

  // Create a TUN device for receiving test packets.
  KTEST_BEGIN("TCP: test setup");
  test_ttap_t tun;
  KEXPECT_EQ(0, test_ttap_create(&tun, TUNTAP_TUN_MODE));

  kspin_lock(&tun.n->lock);
  nic_add_addr(tun.n, SRC_IP, 24, NIC_ADDR_ENABLED);
  nic_add_addr_v6(tun.n, "2001:db8::1", 64, NIC_ADDR_ENABLED);
  kspin_unlock(&tun.n->lock);

  g_tcp_test.tun_fd = tun.fd;
  g_tcp_test.tun_chardev = dev_get_char(tun.nic_id);

  for (int i = 0; i < TEST_SEQ_ITERS; ++i) {
    g_tcp_test.seq_start = TEST_SEQ_START;
    if (TEST_SEQ_ITERS > 1) {
      // We only add the offset if doing more than one iteration.
      g_tcp_test.seq_start += (uint32_t)(i - TEST_SEQ_ITERS / 2);
    }
    klogf("g_seq_start = 0x%x\n", g_tcp_test.seq_start);
    tcp_key_test();
    tcp_v6_key_test();
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
    listen_tests();
    poll_tests();
    retransmit_tests();
    nonblocking_tests();
    close_race_tests();
    open_race_tests();
    tcp_ipv6_tests();
    zero_window_probe_tests();
  }

  // These are tests that don't look specifically at the sequence numbers or
  // manipulate the TCP state machine.
  cwnd_test();
  cwnd_socket_test();
  nonblocking_tap_test();
  connect_sockets_tests();
  reuseaddr_tests();
  rapid_reconnect_test();
  sockmap_tests();
  multithread_test();

  KTEST_BEGIN("TCP: test cleanup");
  test_ttap_destroy(&tun);

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());

  // Look for sockets that are not attached to an FD but are still open.
  KTEST_BEGIN("TCP: socket leak verification");
  KEXPECT_EQ(initial_sockets, tcp_num_connected_sockets());

  if (TCP_ENABLE_COVERAGE) {
    tcp_coverage_dump();
  }
}
