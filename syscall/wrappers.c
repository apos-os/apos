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
