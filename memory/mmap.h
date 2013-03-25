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

#include <stdint.h>

#include "common/types.h"
#include "memory/flags.h"

#define PROT_NONE MEM_PROT_NONE
#define PROT_EXEC MEM_PROT_EXEC
#define PROT_READ MEM_PROT_READ
#define PROT_WRITE MEM_PROT_WRITE
#define PROT_ALL MEM_PROT_ALL

// Exactly one of MAP_SHARED and MAP_PRIVATE must be given.
#define MAP_SHARED 1
#define MAP_PRIVATE 2

// Create a mapping in the current process.
//
// Currently, addr must be NULL, prot must include PORT_EXEC | PROT_READ,
// and flags must be MAP_SHARED.
//
// TODO(aoates): implement protection, private mappings, and other flags (in
// particular, MAP_ANONYMOUS).
int do_mmap(void* addr, addr_t length, int prot, int flags,
            int fd, addr_t offset, void** addr_out);

// Unmap a portion of a previous mapping.
int do_munmap(void* addr, addr_t length);

#endif
