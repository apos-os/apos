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

// Structs and wrappers for syscalls from 32-bit programs into a 64-bit kernel.
#ifndef APOO_SYSCALL_WRAPPERS32_H
#define APOO_SYSCALL_WRAPPERS32_H

#include "common/types.h"

int mmap_wrapper_32(void* addr_inout, addr_t length, int prot, int flags,
                    int fd, addr_t offset);

#endif
