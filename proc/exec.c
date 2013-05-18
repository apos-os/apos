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

#include <stddef.h>

#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "proc/exec.h"
#include "proc/load/load.h"
#include "proc/user_mode.h"
#include "vfs/vfs.h"

int do_exec(const char* path) {
  const int fd = vfs_open(path, VFS_O_RDONLY);
  if (fd < 0) {
    klogf("exec error: couldn't open file '%s' for reading: %s\n", path,
          errorname(-fd));
    return fd;
  }

  // Load the binary.
  load_binary_t* binary = NULL;
  int result = load_binary(fd, &binary);
  if (result) {
    klogf("exec error: couldn't load binary from file '%s': %s\n", path,
          errorname(-result));
    return result;
  }

  // Unmap the current user address space.
  // TODO(aoates): if this (or anything after this) fails, we're hosed.  Should
  // exit the process.
  result = do_munmap((void*)MEM_FIRST_MAPPABLE_ADDR,
                     MEM_LAST_USER_MAPPABLE_ADDR -
                     MEM_FIRST_MAPPABLE_ADDR + 1);
  if (result) {
    kfree(binary);
    klogf("exec error: couldn't unmap existing user code: %s\n",
          errorname(-result));
    return result;
  }

  // Map the data into our address space.
  result = load_map_binary(fd, binary);
  if (result) {
    kfree(binary);
    klogf("exec error: couldn't map new user code: %s\n", errorname(-result));
    return result;
  }
  vfs_close(fd);

  // Create the stack.
  void* stack_addr_out;
  result = do_mmap((void*)MEM_USER_STACK_BOTTOM, MEM_USER_STACK_SIZE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                   -1, 0, &stack_addr_out);
  if (result) {
    kfree(binary);
    klogf("exec error: couldn't create mapping for kernel stack: %s\n",
          errorname(-result));
    return result;
  }

  // Jump to the entry point.
  const addr_t entry = binary->entry;
  kfree(binary);

  const addr_t stack_top =
      (MEM_USER_STACK_BOTTOM + MEM_USER_STACK_SIZE - sizeof(addr_t));
  user_mode_enter(stack_top, entry);

  // We shouldn't ever get here, since we can't return from user space.
  die("Returned to exec() after jmp into user mode!");
  return 0;
}
