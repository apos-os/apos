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
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/mmap.h"
#include "proc/exec.h"
#include "proc/load/load.h"
#include "proc/user_mode.h"
#include "vfs/vfs.h"

#define MAX_ARGV_ENVP_SIZE (MEM_USER_STACK_SIZE / 4)

#define KLOG(...) klogfm(KL_PROC, __VA_ARGS__)

// Copy the given string table to the stack, updating the stack top pointer.
// A copy of the table (with updated pointers) will be placed near the original
// stack top, pointing to copies of all the strings located in the stack.  The
// actual address of the table copy will be stored in |table_out_ptr|.
static int copy_string_table(addr_t* stack_top_ptr, char* const table[],
                             addr_t* table_out_ptr) {
  KASSERT((*stack_top_ptr) % sizeof(addr_t) == 0);

  addr_t* table_copy = (addr_t*)(*stack_top_ptr);
  int copied = 0;

  // Make a copy of the table first.
  for (int i = 0; table[i] != NULL; ++i) {
    copied += sizeof(addr_t);
    if (copied >= MAX_ARGV_ENVP_SIZE) return -E2BIG;

    *(table_copy - i) = 0x0;
    (*stack_top_ptr) -= sizeof(addr_t);
  }

  // Final NULL entry.
  copied += sizeof(addr_t);
  if (copied >= MAX_ARGV_ENVP_SIZE) return -E2BIG;
  *((addr_t*)(*stack_top_ptr)) = 0x0;
  (*stack_top_ptr) -= sizeof(addr_t);

  *table_out_ptr = *stack_top_ptr;

  // Copy each string.
  for (int i = 0; table[i] != NULL; ++i) {
    const int len = kstrlen(table[i]);
    if (copied + len >= MAX_ARGV_ENVP_SIZE) return -E2BIG;
    (*stack_top_ptr) -= len + 1;
    kstrcpy((void*)(*stack_top_ptr), table[i]);
    ((addr_t*)(*table_out_ptr))[i] = (addr_t)(*stack_top_ptr);
  }

  // Align the stack top appropriately.  Align to next lowest word, then add a
  // padding word for good measure.
  // TODO(aoates): how do we do this in a platform-independent way?
  (*stack_top_ptr) -= sizeof(addr_t) + (*stack_top_ptr) % sizeof(addr_t);

  return 0;
}

int do_execve(const char* path, char* const argv[], char* const envp[],
              void (*cleanup)(const char* path,
                              char* const argv[], char* const envp[],
                              void* arg), void* cleanup_arg) {
  const int fd = vfs_open(path, VFS_O_RDONLY | VFS_O_INTERNAL_EXEC);
  if (fd < 0) {
    KLOG(INFO, "exec error: couldn't open file '%s' for reading: %s\n", path,
         errorname(-fd));
    return fd;
  }

  // Load the binary.
  load_binary_t* binary = NULL;
  int result = load_binary(fd, &binary);
  if (result) {
    KLOG(INFO, "exec error: couldn't load binary from file '%s': %s\n", path,
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
    KLOG(INFO, "exec error: couldn't unmap existing user code: %s\n",
         errorname(-result));
    return result;
  }

  // Map the data into our address space.
  result = load_map_binary(fd, binary);
  if (result) {
    kfree(binary);
    KLOG(INFO, "exec error: couldn't map new user code: %s\n",
         errorname(-result));
    return result;
  }
  vfs_close(fd);

  // Reset any custom signal handlers to the default.
  for (int signo = SIGMIN; signo <= SIGMAX; ++signo) {
    sigaction_t* action = &proc_current()->signal_dispositions[signo];
    if (action->sa_handler != SIG_DFL && action->sa_handler != SIG_IGN) {
      // TODO(aoates): should we reset the flags and mask as well?
      action->sa_handler = SIG_DFL;
    }
  }

  // TODO(aoates): handle set-user-ID/set-group-ID bits.
  proc_current()->suid = proc_current()->euid;
  proc_current()->sgid = proc_current()->egid;

  // Create the stack.
  void* stack_addr_out;
  result = do_mmap((void*)MEM_USER_STACK_BOTTOM, MEM_USER_STACK_SIZE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                   -1, 0, &stack_addr_out);
  if (result) {
    kfree(binary);
    KLOG(INFO, "exec error: couldn't create mapping for kernel stack: %s\n",
         errorname(-result));
    return result;
  }

  // Copy argv and envp to the new stack.
  addr_t stack_top =
      (MEM_USER_STACK_BOTTOM + MEM_USER_STACK_SIZE - sizeof(addr_t));
  addr_t argv_addr = 0x0;
  result = copy_string_table(&stack_top, argv, &argv_addr);
  if (result) {
    kfree(binary);
    return result;
  }
  addr_t envp_addr = 0x0;
  result = copy_string_table(&stack_top, envp, &envp_addr);
  if (result) {
    kfree(binary);
    return result;
  }

  // Push argv and envp onto the stack to pass to the program.
  stack_top -= stack_top % sizeof(addr_t);
  *(addr_t*)(stack_top -= sizeof(addr_t)) = envp_addr;
  *(addr_t*)(stack_top -= sizeof(addr_t)) = argv_addr;
  *(addr_t*)(stack_top -= sizeof(addr_t)) = 0x0;  // Fake return address.

  if (cleanup) {
    (*cleanup)(path, argv, envp, cleanup_arg);
  }

  // Jump to the entry point.
  const addr_t entry = binary->entry;
  kfree(binary);

  proc_current()->execed = 1;

  user_mode_enter(stack_top, entry);

  // We shouldn't ever get here, since we can't return from user space.
  die("Returned to exec() after jmp into user mode!");
  return 0;
}
