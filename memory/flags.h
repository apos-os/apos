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

// Common flags for memory operations.
#ifndef APOO_MEMORY_FLAGS_H
#define APOO_MEMORY_FLAGS_H

// Protection flags.  Not all are supported on all platforms.
#define MEM_PROT_NONE 0x00
#define MEM_PROT_READ 0x01
#define MEM_PROT_WRITE 0x02
#define MEM_PROT_EXEC 0x04
#define MEM_PROT_ALL (MEM_PROT_READ | MEM_PROT_WRITE | MEM_PROT_EXEC)

// Who can access a memory location.
#define MEM_ACCESS_KERNEL_ONLY 0
#define MEM_ACCESS_KERNEL_AND_USER 1

// Other misc. flags.
#define MEM_GLOBAL 0x01  // A global (across all processes) mapping.

#endif
