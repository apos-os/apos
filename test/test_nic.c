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
#include "test/test_nic.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "dev/net/nic.h"
#include "dev/net/tuntap.h"
#include "net/util.h"
#include "proc/spinlock.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

#define TAP_BUFSIZE 5000

int test_ttap_create(test_ttap_t* t, int flags) {
  t->fd = -1;
  t->n = tuntap_create(TAP_BUFSIZE, flags, &t->nic_id);
  if (t->n == NULL) {
    klogfm(KL_TEST, WARNING, "test_ttap_create(): unable to create NIC\n");
    return -EXDEV;
  }
  mac2str(t->n->mac.addr, t->mac);


  char fname[NIC_MAX_NAME_LEN + 20];
  ksprintf(fname, "_tap_test_dev_%s", t->n->name);
  int result = vfs_mknod(fname, VFS_S_IFCHR | VFS_S_IRWXU, t->nic_id);
  if (result  < 0) {
    klogfm(KL_TEST, WARNING,
           "test_ttap_create(): unable to create device file: %s\n",
           errorname(-result));
    test_ttap_destroy(t);
    return result;
  }
  t->fd = vfs_open(fname, VFS_O_RDWR);
  KASSERT(0 == vfs_unlink(fname));
  if (t->fd < 0) {
    klogfm(KL_TEST, WARNING,
           "test_ttap_create(): unable to open device file %s: %s\n", fname,
           errorname(-t->fd));
    test_ttap_destroy(t);
    return t->fd;
  }

  vfs_make_nonblock(t->fd);
  return 0;
}

void test_ttap_destroy(test_ttap_t* t) {
  if (t->fd >= 0) {
    KASSERT(0 == vfs_close(t->fd));
  }
  KASSERT(0 == tuntap_destroy(t->nic_id));
  t->n = NULL;
}

bool test_ttap_mc_subscribed(const test_ttap_t* tt, const nic_mac_t* mac) {
  return tuntap_mc_subscribed(tt->n, mac);
}

static nic_addr_t* alloc_addr(nic_t* nic, int prefix_len,
                              nic_addr_state_t state) {
  KASSERT(kspin_is_held(&nic->lock));
  for (int i = 0; i < NIC_MAX_ADDRS; ++i) {
    if (nic->addrs[i].state == NIC_ADDR_NONE) {
      nic->addrs[i].a.prefix_len = prefix_len;
      nic->addrs[i].state = state;
      return &nic->addrs[i];
    }
  }
  die("NIC has too many addresses");
}

nic_addr_t* nic_add_addr(nic_t* nic, const char* ipv4, int prefix_len,
                         nic_addr_state_t state) {
  KASSERT(kspin_is_held(&nic->lock));
  // Sanity check to make sure IPv6 addresses aren't passed.
  KASSERT(kstrchr(ipv4, ':') == 0);
  KASSERT(prefix_len >= 0);
  KASSERT(prefix_len <= 32);
  nic_addr_t* addr = alloc_addr(nic, prefix_len, state);
  addr->a.addr.family = ADDR_INET;
  addr->a.addr.a.ip4.s_addr = str2inet(ipv4);
  return addr;
}

nic_addr_t* nic_add_addr_v6(nic_t* nic, const char* ipv6, int prefix_len,
                            nic_addr_state_t state) {
  KASSERT(kspin_is_held(&nic->lock));
  // Sanity check to make sure IPv4 addresses aren't passed.
  KASSERT(kstrchr(ipv6, '.') == 0);
  KASSERT(prefix_len >= 0);
  KASSERT(prefix_len <= 128);
  nic_addr_t* addr = alloc_addr(nic, prefix_len, state);
  addr->a.addr.family = ADDR_INET6;
  KASSERT(0 == str2inet6(ipv6, &addr->a.addr.a.ip6));
  return addr;
}
