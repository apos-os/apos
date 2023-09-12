// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "memory/mmap.h"
#include "proc/exec.h"
#include "proc/process.h"
#include "syscall/dmz.h"
#include "syscall/wrappers.h"

kpid_t getpid_wrapper(void) {
  return proc_current()->id;
}

kpid_t getppid_wrapper(void) {
  if (proc_current()->parent) {
    return proc_current()->parent->id;
  } else {
    return proc_current()->id;
  }
}

_Static_assert(sizeof(apos_off_t) <= sizeof(addr_t),
               "Narrowing conversion from apos_off_t to addr_t.");
int mmap_wrapper(void* addr_inout, size_t length, int prot, int flags,
                 int fd, apos_off_t offset) {
  void* addr = *(void**)addr_inout;
  return do_mmap(addr, length, prot, flags, fd, offset, (void**)addr_inout);
}

int accept_wrapper(int socket, struct sockaddr* addr, socklen_t* addr_len) {
  // Everything is checked but the 'addr' argument.  Do that now.
  struct sockaddr* KERNEL_addr = 0x0;

  if (addr_len != NULL && (size_t)(*addr_len) > UINT32_MAX / 2) {
    return -EINVAL;
  }

  if (addr_len == NULL) {
    // If the length is NULL, ignore the addr buffer.
    addr = NULL;
  }

  KERNEL_addr = !addr ? 0x0 : (struct sockaddr*)kmalloc(*addr_len);
  if (addr && !KERNEL_addr) {
    return -ENOMEM;
  }

  int result = net_accept(socket, KERNEL_addr, addr_len);

  if (addr) {
    int copy_result = syscall_copy_to_user(KERNEL_addr, addr, *addr_len);
    if (copy_result) result = copy_result;
  }
  if (KERNEL_addr) kfree((void*)KERNEL_addr);

  return result;
}

ssize_t recvfrom_wrapper(int socket, void* buf, size_t len, int flags,
                         struct sockaddr* address, socklen_t* address_len) {
  struct sockaddr* KERNEL_address = 0x0;

  if (address_len != NULL && (size_t)(*address_len) > UINT32_MAX / 2) {
    return -EINVAL;
  }

  if (address_len == NULL) {
    // If the length is NULL, ignore the addr buffer.
    address = NULL;
  }

  KERNEL_address = !address ? 0x0 : (struct sockaddr*)kmalloc(*address_len);
  if (address && !KERNEL_address) {
    return -ENOMEM;
  }

  int result =
      net_recvfrom(socket, buf, len, flags, KERNEL_address, address_len);

  if (address) {
    result = syscall_copy_to_user(KERNEL_address, address, *address_len);
  }
  if (KERNEL_address) kfree((void*)KERNEL_address);

  return result;
}

int klog_wrapper(const char* msg) {
  // TODO(aoates): consider checking a capability of some sort.
  klogm(KL_USER, INFO, msg);
  return 0;
}
