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

pid_t getpid_wrapper() {
  return proc_current()->id;
}

pid_t getppid_wrapper() {
  if (proc_current()->parent) {
    return proc_current()->parent->id;
  } else {
    return proc_current()->id;
  }
}

int mmap_wrapper(void* addr_inout, addr_t length, int prot, int flags,
                 int fd, addr_t offset) {
  void* addr = *(void**)addr_inout;
  return do_mmap(addr, length, prot, flags, fd, offset, (void**)addr_inout);
}

int accept_wrapper(int socket, struct sockaddr* addr, socklen_t* addr_len) {
  // Everything is checked but the 'addr' argument.  Do that now.
  struct sockaddr* KERNEL_addr = 0x0;

  if (addr_len != NULL) {
    const int CHECK_addr = syscall_verify_buffer(
        addr, *addr_len, 1 /* is_write */, 1 /* allow_null */);
    if (CHECK_addr < 0) return CHECK_addr;
  } else {
    // If the length is NULL, ignore the addr buffer.
    addr = NULL;
  }

  KERNEL_addr = !addr ? 0x0 : (struct sockaddr*)kmalloc(*addr_len);
  if (addr && !KERNEL_addr) {
    return -ENOMEM;
  }

  const int result = net_accept(socket, KERNEL_addr, addr_len);

  if (addr) kmemcpy(addr, KERNEL_addr, *addr_len);
  if (KERNEL_addr) kfree((void*)KERNEL_addr);

  return result;
}
