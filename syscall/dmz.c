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
#include "common/types.h"
#include "memory/vm.h"
#include "syscall/dmz.h"

int syscall_verify_buffer(const void* buf, size_t len, int is_write) {
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

  addr_t region_end;
  const int result = vm_verify_address(proc_current(), (addr_t)str,
                                       0, 1, &region_end);
  if (result) return result;

  // Look for a NULL in the valid region.
  // TODO(aoates): there's a race here if the user concurrently munmap()s the
  // region containing the string.
  for (addr_t i = 0; (addr_t)str + i < region_end; ++i) {
    if (str[i] == '\0') {
      return i + 1;
    }
  }
  return -EFAULT;
}
