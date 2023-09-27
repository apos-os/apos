// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SYSCALL_DMZ_INTERNAL_H
#define APOO_SYSCALL_DMZ_INTERNAL_H

#include <stdint.h>

#include "memory/memory.h"

// Semi-arbitrary limit on the size of buffers that can be passed to/from
// syscalls, to prevent us trying to allocate huge amounts of memory on behalf
// of bogus syscalls.  Must be at most UINT32_MAX / 2 to catch negative sizes.
#define DMZ_MAX_BUFSIZE (PAGE_SIZE * 256)
_Static_assert(DMZ_MAX_BUFSIZE < UINT32_MAX / 2, "DMZ_MAX_BUFSIZE too large");

#endif
