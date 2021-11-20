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
#include "common/kstring.h"
#include "common/math.h"
#include "common/types.h"
#include "memory/vm.h"
#include "syscall/dmz.h"

int syscall_verify_buffer(const void* buf, size_t len, int is_write,
                          int allow_null) {
  if (!buf && allow_null) {
    return 0;
  }
  if ((addr_t)buf > MEM_LAST_MAPPABLE_ADDR - len) {
    return -EFAULT;
  }

  return vm_verify_region(proc_current(), (addr_t)buf, (addr_t)buf + len,
                          is_write, 1);
}

int syscall_verify_string(const char* str) {
  if (!str) {
    return -EINVAL;
  }

  bc_entry_t* entry = NULL;
  phys_addr_t resolved;
  addr_t user_addr = (addr_t)str;
  size_t offset_in_page = user_addr % PAGE_SIZE;
  size_t result_len = 0;
  bool done = false;
  while (!done) {
    int result = vm_resolve_address(proc_current(), user_addr, /* length= */ 1,
                                    /* is_write= */ false,
                                    /* is_user= */ true, &entry, &resolved);
    if (result) return result;

    const char* entry_buf = (const char*)entry->block;
    for (size_t i = offset_in_page; i < PAGE_SIZE; ++i) {
      result_len++;
      if (entry_buf[i] == '\0') {
        done = true;
        break;
      }
    }

    user_addr += PAGE_SIZE - offset_in_page;
    offset_in_page = 0;
    result = block_cache_put(entry, BC_FLUSH_NONE);
    if (result) {
      // This shouldn't happen.
      klogfm(KL_SYSCALL, WARNING,
             "Unable to put() entry in copy_from_user: %s\n",
             errorname(-result));
      return result;
    }
  }

  return result_len;
}

// TODO(aoates): combine this somehow with syscall_verify_string, which is
// nearly identical.
int syscall_verify_ptr_table(const void* table, bool is64bit) {
  if (!table) {
    return -EINVAL;
  }

  addr_t region_end;
  const int result = vm_verify_address(proc_current(), (addr_t)table,
                                       0, 1, &region_end);
  if (result) return result;

  // Look for a NULL in the valid region.
  // TODO(aoates): there's a race here if the user concurrently munmap()s the
  // region containing the string.
  const addr_t table_base = (addr_t)table;
  const size_t ptr_size = is64bit ? sizeof(addr64_t) : sizeof(addr32_t);
  for (addr_t i = 0; table_base + i * ptr_size < region_end; ++i) {
    addr64_t ptr = is64bit ? ((addr64_t*)table)[i] : ((addr32_t*)table)[i];
    if (ptr == 0x0) {
      return i + 1;
    }
  }
  return -EFAULT;
}

static int syscall_copy_user_helper(addr_t user_addr, addr_t kernel_addr,
                                    size_t len, bool is_from_user) {
  bc_entry_t* entry = NULL;
  phys_addr_t resolved;
  size_t offset_in_page = user_addr % PAGE_SIZE;
  const bool is_write = !is_from_user;
  while (len > 0) {
    int result = vm_resolve_address(proc_current(), user_addr, /* length= */ 1,
                                    /* is_write= */ is_write,
                                    /* is_user= */ true, &entry, &resolved);
    if (result) return result;
    size_t bytes_to_copy = min(len, PAGE_SIZE - offset_in_page);
    // TODO(aoates): consider copying from the physical memory directly to
    // clearly avoid any races with memory map changes.
    if (is_from_user) {
      kmemcpy((void*)kernel_addr, (void*)user_addr, bytes_to_copy);
    } else {
      kmemcpy((void*)user_addr, (void*)kernel_addr, bytes_to_copy);
    }
    len -= bytes_to_copy;
    offset_in_page = 0;
    user_addr += bytes_to_copy;
    kernel_addr += bytes_to_copy;
    // TODO(aoates): write a test that catches the wrong flush mode here.
    result = block_cache_put(entry, is_write ? BC_FLUSH_ASYNC : BC_FLUSH_NONE);
    if (result) {
      // This shouldn't happen.
      klogfm(KL_SYSCALL, WARNING,
             "Unable to put() entry in copy_from_user: %s\n",
             errorname(-result));
      return result;
    }
  }
  return 0;
}

int syscall_copy_from_user(const void* from_user, void* to, size_t len) {
  return syscall_copy_user_helper((addr_t)from_user, (addr_t)to, len, true);
}

int syscall_copy_to_user(const void* from, void* to_user, size_t len) {
  return syscall_copy_user_helper((addr_t)to_user, (addr_t)from, len, false);
}
