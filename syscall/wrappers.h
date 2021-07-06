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

// Small wrappers for syscalls.
#ifndef APOO_SYSCALL_WRAPPERS_H
#define APOO_SYSCALL_WRAPPERS_H

#include <stdint.h>

#include "proc/exit.h"
#include "user/include/apos/dev.h"
#include "vfs/vfs.h"

// TODO(aoates): if we have more void syscalls, we should add support directly
// to the syscall templates.
static inline int proc_exit_wrapper(int status) {
  proc_exit(status);
  return 0;  // Should never get here.
}

kpid_t getpid_wrapper(void);
kpid_t getppid_wrapper(void);

// Wrapper for do_mmap that combines the address in and out arguments to squeeze
// into the syscall limit.
int mmap_wrapper(void* addr_inout, addr_t length, int prot, int flags,
                 int fd, addr_t offset);

// Wrappers for syscalls that pass a R/W buffer with the size of another buffer
// inside them.  If there are more of these we should consider autogenerating
// this.
int accept_wrapper(int socket, struct sockaddr* addr, socklen_t* addr_len);
ssize_t recvfrom_wrapper(int socket, void* buf, size_t len, int flags,
                         struct sockaddr* address, socklen_t* address_len);

int klog_wrapper(const char* msg);

#endif
