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

#ifndef APOO_MEMORY_MMAP_H
#define APOO_MEMORY_MMAP_H

#include <stddef.h>
#include <stdint.h>

#include "common/types.h"
#include "memory/flags.h"
#include "user/include/apos/mmap.h"

// Create a mapping in the current process.
//
// Currently, addr must be NULL, prot must include PORT_EXEC | PROT_READ,
// and flags must be MAP_SHARED and a combination of other flags.
int do_mmap(void* addr, addr_t length, int prot, int flags,
            int fd, addr_t offset, void** addr_out);

// Unmap a portion of a previous mapping.
int do_munmap(void* addr, addr_t length);

// Return current mmap usage (as limited by RLIMIT_AS).
size_t mmap_get_usage(void);
size_t mmap_get_usage_locked(void);  // REQUIRES(proc_current()->mu)

#endif
