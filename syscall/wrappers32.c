// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#include "memory/mmap.h"
#include "syscall/wrappers32.h"

int mmap_wrapper_32(void* addr_inout32, addr_t length, int prot, int flags,
                    int fd, addr_t offset) {
  void* addr = (void*)(addr_t)*(uint32_t*)addr_inout32;
  void* addr_out = NULL;
  int result = do_mmap(addr, length, prot, flags, fd, offset, &addr_out);
  // TODO(aoates): enforce 32-bit only mappings in mmap.
  *(uint32_t*)addr_inout32 = (addr_t)addr_out;
  return result;
}
