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

#include "dev/net/tuntap.h"

#include "common/endian.h"
#include "dev/net/nic.h"
#include "net/eth/arp/arp_cache_ops.h"
#include "net/eth/eth.h"
#include "net/ip/ip4_hdr.h"
#include "net/pbuf.h"
#include "net/socket/socket.h"
#include "net/socket/udp.h"
#include "net/util.h"
#include "proc/kthread.h"
#include "proc/notification.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "test/ktest.h"
#include "user/include/apos/net/socket/inet.h"
#include "user/include/apos/vfs/poll.h"
#include "user/include/apos/vfs/vfs.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define BUFSIZE 500
#define SRC_IP "127.0.5.1"
#define DST_IP "127.0.5.2"

#define THREAD_BUF_SIZE 50

typedef struct {
  int sock;
  int tt_fd;
  nic_t* nic;

  notification_t thread_started;
  notification_t thread_done;
  int thread_result;
  char thread_buf[THREAD_BUF_SIZE];
  int poll_events;
} test_fixture_t;

static void basic_tx_test(test_fixture_t* f) {
  KTEST_BEGIN("TUN/TAP: basic TX test (to NIC's IP)");
  struct sockaddr_in dst = str2sin(DST_IP, 5678);
  KEXPECT_EQ(
      3, net_sendto(f->sock, "abc", 3, 0, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_EQ(
      2, net_sendto(f->sock, "de", 2, 0, (struct sockaddr*)&dst, sizeof(dst)));

  // We should get an IP header, a UDP header, and some data.
  char* buf = kmalloc(BUFSIZE);
  kmemset(buf, 0, BUFSIZE);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  const ip4_hdr_t* ip4_hdr = (const ip4_hdr_t*)buf;
  KEXPECT_EQ(ip4_hdr->src_addr, str2inet(SRC_IP));
  KEXPECT_EQ(ip4_hdr->dst_addr, str2inet(DST_IP));
  KEXPECT_EQ(IPPROTO_UDP, ip4_hdr->protocol);

  const udp_hdr_t* udp_hdr = (const udp_hdr_t*)(buf + sizeof(ip4_hdr_t));
  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(5678, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("abc", buf + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t));

  // Test the second packet.
  kmemset(buf, 0, BUFSIZE);
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 2,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(ip4_hdr->src_addr, str2inet(SRC_IP));
  KEXPECT_EQ(ip4_hdr->dst_addr, str2inet(DST_IP));
  KEXPECT_EQ(IPPROTO_UDP, ip4_hdr->protocol);

  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(5678, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ("de", buf + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t));


  KTEST_BEGIN("TUN/TAP: bufsize is enforced (drops extra packets)");
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  // These two should silently fail (drop the packet).
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));

  // On the other end, should only get two packets.
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 200,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 200,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(-EAGAIN, vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(-EAGAIN, vfs_read(f->tt_fd, buf, BUFSIZE));

  // ...but now should be able to transmit again.
  KEXPECT_EQ(200, net_sendto(f->sock, buf, 200, 0, (struct sockaddr*)&dst,
                             sizeof(dst)));
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 200,
             vfs_read(f->tt_fd, buf, BUFSIZE));
  KEXPECT_EQ(-EAGAIN, vfs_read(f->tt_fd, buf, BUFSIZE));

  kfree(buf);
}

static void* do_read(void* arg) {
  test_fixture_t* f = (test_fixture_t*)arg;
  ntfn_notify(&f->thread_started);
  f->thread_result = vfs_read(f->tt_fd, &f->thread_buf, THREAD_BUF_SIZE);
  ntfn_notify(&f->thread_done);
  return NULL;
}

static void blocking_read_test(test_fixture_t* f) {
  KTEST_BEGIN("TUN/TAP: read() blocks until packets are available");
  vfs_make_blocking(f->tt_fd);

  ntfn_init(&f->thread_started);
  ntfn_init(&f->thread_done);
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_read, f));
  KEXPECT_FALSE(ntfn_await_with_timeout(&f->thread_done, 50));

  struct sockaddr_in dst = str2sin(DST_IP, 5678);
  KEXPECT_EQ(
      3, net_sendto(f->sock, "abc", 3, 0, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_TRUE(ntfn_await_with_timeout(&f->thread_done, 5000));

  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             f->thread_result);
  KEXPECT_EQ(NULL, kthread_join(thread));


  KTEST_BEGIN("TUN/TAP: read() blocks, interrupted");
  ntfn_init(&f->thread_started);
  ntfn_init(&f->thread_done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_read, f));
  KEXPECT_TRUE(ntfn_await_with_timeout(&f->thread_started, 5000));

  KEXPECT_EQ(0, proc_kill_thread(thread, SIGUSR1));
  KEXPECT_TRUE(ntfn_await_with_timeout(&f->thread_done, 5000));

  KEXPECT_EQ(-EINTR, f->thread_result);
  KEXPECT_EQ(NULL, kthread_join(thread));


  KTEST_BEGIN("TUN/TAP: read() multi-thread race");
  ntfn_init(&f->thread_started);
  ntfn_init(&f->thread_done);
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_read, f));
  KEXPECT_TRUE(ntfn_await_with_timeout(&f->thread_started, 5000));
  kthread_disable(thread);

  KEXPECT_EQ(
      3, net_sendto(f->sock, "abc", 3, 0, (struct sockaddr*)&dst, sizeof(dst)));
  // The other thread should be notified and wake up, but not run.
  ksleep(10);
  // We steal the packet.
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(f->tt_fd, &f->thread_buf, THREAD_BUF_SIZE));
  kthread_enable(thread);
  KEXPECT_FALSE(ntfn_await_with_timeout(&f->thread_done, 10));

  // Let the other thread get one now.
  KEXPECT_EQ(
      2, net_sendto(f->sock, "de", 2, 0, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_TRUE(ntfn_await_with_timeout(&f->thread_done, 5000));

  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 2, f->thread_result);
  KEXPECT_EQ(NULL, kthread_join(thread));

  vfs_make_nonblock(f->tt_fd);
}

static void basic_rx_test(test_fixture_t* f) {
  KTEST_BEGIN("TUN/TAP: basic RX test");

  // We should get an IP header, a UDP header, and some data.
  pbuf_t* pb = pbuf_create(INET_HEADER_RESERVE + sizeof(udp_hdr_t), 3);
  kmemcpy(pbuf_get(pb), "abc", 3);

  pbuf_push_header(pb, sizeof(udp_hdr_t));
  udp_hdr_t* udp_hdr = (udp_hdr_t*)pbuf_get(pb);

  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + 3);
  udp_hdr->checksum = 0;

  ip4_add_hdr(pb, str2inet(DST_IP), str2inet(SRC_IP), IPPROTO_UDP);

  KEXPECT_EQ(pbuf_size(pb), vfs_write(f->tt_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);

  char buf[10];
  KEXPECT_EQ(3, vfs_read(f->sock, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);
}

static void* do_poll(void* arg) {
  test_fixture_t* f = (test_fixture_t*)arg;
  ntfn_notify(&f->thread_started);
  struct apos_pollfd pfd;
  pfd.fd = f->tt_fd;
  pfd.events = f->poll_events;
  pfd.revents = 0;
  f->thread_result = vfs_poll(&pfd, 1, 5000);
  f->poll_events = pfd.revents;
  ntfn_notify(&f->thread_done);
  return NULL;
}

static void poll_test(test_fixture_t* f) {
  KTEST_BEGIN("TUN/TAP: poll test");

  ntfn_init(&f->thread_started);
  ntfn_init(&f->thread_done);
  f->poll_events = KPOLLIN | KPOLLHUP | KPOLLRDBAND | KPOLLRDNORM | KPOLLPRI;
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll, f));
  KEXPECT_FALSE(ntfn_await_with_timeout(&f->thread_done, 10));

  struct sockaddr_in dst = str2sin(DST_IP, 5678);
  KEXPECT_EQ(
      3, net_sendto(f->sock, "abc", 3, 0, (struct sockaddr*)&dst, sizeof(dst)));
  KEXPECT_TRUE(ntfn_await_with_timeout(&f->thread_done, 3000));

  KEXPECT_EQ(1, f->thread_result);
  KEXPECT_EQ(KPOLLIN, f->thread_result);
  KEXPECT_EQ(NULL, kthread_join(thread));

  struct apos_pollfd pfd;
  pfd.fd = f->tt_fd;
  pfd.events = KPOLLIN | KPOLLOUT;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 1000));
  KEXPECT_EQ(KPOLLIN | KPOLLOUT, pfd.revents);

  char buf[40];
  KEXPECT_EQ(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(f->tt_fd, buf, 40));

  pfd.events = KPOLLIN | KPOLLOUT;
  pfd.revents = 0;
  KEXPECT_EQ(1, vfs_poll(&pfd, 1, 1000));
  KEXPECT_EQ(KPOLLOUT, pfd.revents);

  pfd.events = KPOLLIN;
  pfd.revents = 0;
  KEXPECT_EQ(0, vfs_poll(&pfd, 1, 0));
}

static void tun_tests(void) {
  KTEST_BEGIN("TUN: test setup");
  test_fixture_t fixture;
  apos_dev_t id;
  nic_t* nic = tuntap_create(BUFSIZE, 0, &id);
  KEXPECT_NE(NULL, nic);

  kspin_lock(&nic->lock);
  nic->addrs[0].addr.family = ADDR_INET;
  nic->addrs[0].addr.a.ip4.s_addr = str2inet(SRC_IP);
  nic->addrs[0].prefix_len = 24;
  kspin_unlock(&nic->lock);

  KEXPECT_EQ(0, vfs_mknod("_tuntap_test_dev", VFS_S_IFCHR | VFS_S_IRWXU, id));
  fixture.tt_fd = vfs_open("_tuntap_test_dev", VFS_O_RDWR);
  KEXPECT_GE(fixture.tt_fd, 0);
  vfs_make_nonblock(fixture.tt_fd);

  fixture.sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(fixture.sock, 0);

  struct sockaddr_in src = str2sin("0.0.0.0", 1234);
  KEXPECT_EQ(0, net_bind(fixture.sock, (struct sockaddr*)&src, sizeof(src)));

  basic_tx_test(&fixture);
  blocking_read_test(&fixture);
  basic_rx_test(&fixture);
  poll_test(&fixture);

  KTEST_BEGIN("TUN: test teardown");
  // Send some more packets to make sure we delete queued packets.
  struct sockaddr_in dst = str2sin(DST_IP, 5678);
  KEXPECT_EQ(3, net_sendto(fixture.sock, "abc", 3, 0, (struct sockaddr*)&dst,
                           sizeof(dst)));
  KEXPECT_EQ(3, net_sendto(fixture.sock, "def", 3, 0, (struct sockaddr*)&dst,
                           sizeof(dst)));

  // Also start an async poll().
  ntfn_init(&fixture.thread_started);
  ntfn_init(&fixture.thread_done);
  fixture.poll_events = 0;
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_poll, &fixture));
  KEXPECT_FALSE(ntfn_await_with_timeout(&fixture.thread_done, 10));

  KEXPECT_EQ(0, vfs_close(fixture.sock));
  KEXPECT_EQ(0, vfs_close(fixture.tt_fd));
  KEXPECT_EQ(0, vfs_unlink("_tuntap_test_dev"));
  KEXPECT_EQ(0, tuntap_destroy(id));

  KEXPECT_TRUE(ntfn_await_with_timeout(&fixture.thread_done, 3000));
  KEXPECT_EQ(1, fixture.thread_result);
  KEXPECT_EQ(KPOLLNVAL, fixture.poll_events);
  KEXPECT_EQ(NULL, kthread_join(thread));
}

static void tap_tx_test(test_fixture_t* f) {
  KTEST_BEGIN("TAP: basic TX test (to NIC's IP)");
  struct sockaddr_in dst = str2sin(DST_IP, 5678);

  // First, seed the ARP cache.
  uint8_t remote_mac[NIC_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  arp_cache_insert(f->nic, dst.sin_addr.s_addr, remote_mac);

  KEXPECT_EQ(
      3, net_sendto(f->sock, "abc", 3, 0, (struct sockaddr*)&dst, sizeof(dst)));

  // We should get an ethernet header, IP header, UDP header, and some data.
  char* buf = kmalloc(BUFSIZE);
  kmemset(buf, 0, BUFSIZE);
  KEXPECT_EQ(sizeof(eth_hdr_t) + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + 3,
             vfs_read(f->tt_fd, buf, BUFSIZE));

  const eth_hdr_t* eth_hdr = (const eth_hdr_t*)buf;
  KEXPECT_EQ(ET_IPV4, btoh16(eth_hdr->ethertype));
  char macstr1[NIC_MAC_PRETTY_LEN], macstr2[NIC_MAC_PRETTY_LEN];
  KEXPECT_STREQ(mac2str(f->nic->mac, macstr1),
                mac2str(eth_hdr->mac_src, macstr2));
  KEXPECT_STREQ("01:02:03:04:05:06", mac2str(eth_hdr->mac_dst, macstr1));

  const ip4_hdr_t* ip4_hdr = (const ip4_hdr_t*)(buf + sizeof(eth_hdr_t));
  KEXPECT_EQ(ip4_hdr->src_addr, str2inet(SRC_IP));
  KEXPECT_EQ(ip4_hdr->dst_addr, str2inet(DST_IP));
  KEXPECT_EQ(IPPROTO_UDP, ip4_hdr->protocol);

  const udp_hdr_t* udp_hdr =
      (const udp_hdr_t*)(buf + sizeof(eth_hdr_t) + sizeof(ip4_hdr_t));
  KEXPECT_EQ(1234, btoh16(udp_hdr->src_port));
  KEXPECT_EQ(5678, btoh16(udp_hdr->dst_port));
  KEXPECT_STREQ(
      "abc", buf + sizeof(eth_hdr_t) + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t));

  kfree(buf);
}

static void tap_rx_test(test_fixture_t* f) {
  KTEST_BEGIN("TAP: basic RX test");

  pbuf_t* pb = pbuf_create(INET_HEADER_RESERVE + sizeof(udp_hdr_t), 3);
  kmemcpy(pbuf_get(pb), "abc", 3);

  pbuf_push_header(pb, sizeof(udp_hdr_t));
  udp_hdr_t* udp_hdr = (udp_hdr_t*)pbuf_get(pb);

  udp_hdr->src_port = htob16(5678);
  udp_hdr->dst_port = htob16(1234);
  udp_hdr->len = htob16(sizeof(udp_hdr_t) + 3);
  udp_hdr->checksum = 0;

  ip4_add_hdr(pb, str2inet(DST_IP), str2inet(SRC_IP), IPPROTO_UDP);

  uint8_t remote_mac[NIC_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  eth_add_hdr(pb, f->nic->mac, remote_mac, ET_IPV4);

  KEXPECT_EQ(pbuf_size(pb), vfs_write(f->tt_fd, pbuf_getc(pb), pbuf_size(pb)));
  pbuf_free(pb);

  char buf[10];
  KEXPECT_EQ(3, vfs_read(f->sock, buf, 10));
  buf[3] = '\0';
  KEXPECT_STREQ("abc", buf);
}

// For TAP mode, we test just the basics and assume TUN mode tests handle
// everything else.
static void tap_tests(void) {
  KTEST_BEGIN("TAP: test setup");
  test_fixture_t fixture;
  apos_dev_t id;
  nic_t* nic = tuntap_create(BUFSIZE, TUNTAP_TAP_MODE, &id);
  KEXPECT_NE(NULL, nic);
  fixture.nic = nic;

  kspin_lock(&nic->lock);
  nic->addrs[0].addr.family = ADDR_INET;
  nic->addrs[0].addr.a.ip4.s_addr = str2inet(SRC_IP);
  nic->addrs[0].prefix_len = 24;
  kspin_unlock(&nic->lock);

  KEXPECT_EQ(0, vfs_mknod("_tuntap_test_dev", VFS_S_IFCHR | VFS_S_IRWXU, id));
  fixture.tt_fd = vfs_open("_tuntap_test_dev", VFS_O_RDWR);
  KEXPECT_GE(fixture.tt_fd, 0);
  vfs_make_nonblock(fixture.tt_fd);

  fixture.sock = net_socket(AF_INET, SOCK_DGRAM, 0);
  KEXPECT_GE(fixture.sock, 0);
  vfs_make_nonblock(fixture.sock);

  struct sockaddr_in src = str2sin("0.0.0.0", 1234);
  KEXPECT_EQ(0, net_bind(fixture.sock, (struct sockaddr*)&src, sizeof(src)));

  tap_tx_test(&fixture);
  tap_rx_test(&fixture);

  KTEST_BEGIN("TAP: test teardown");
  KEXPECT_EQ(0, vfs_close(fixture.sock));
  KEXPECT_EQ(0, vfs_close(fixture.tt_fd));
  KEXPECT_EQ(0, vfs_unlink("_tuntap_test_dev"));
  KEXPECT_EQ(0, tuntap_destroy(id));
}

void tuntap_test(void) {
  KTEST_SUITE_BEGIN("TUN/TAP tests");

  KTEST_BEGIN("TUN/TAP: bad creation args");
  apos_dev_t id;
  KEXPECT_EQ(NULL, tuntap_create(BUFSIZE, 100, &id));
  KEXPECT_EQ(NULL, tuntap_create(0, 0, &id));
  KEXPECT_EQ(NULL, tuntap_create(-1, 0, &id));
  KEXPECT_EQ(NULL, tuntap_create(BUFSIZE, 0, NULL));
  KEXPECT_EQ(NULL, tuntap_create(100, 0, &id));

  tun_tests();
  tap_tests();
}
