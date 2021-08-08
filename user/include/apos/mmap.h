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

#ifndef APOO_USER_MMAP_H
#define APOO_USER_MMAP_H

// Memory protection flags.
#define KPROT_NONE 0x00
#define KPROT_READ 0x01
#define KPROT_WRITE 0x02
#define KPROT_EXEC 0x04

// Exactly one of MAP_SHARED and MAP_PRIVATE must be given.
#define KMAP_SHARED 0x01
#define KMAP_PRIVATE 0x02

// Other flags.
#define KMAP_FIXED 0x04
#define KMAP_ANONYMOUS 0x08
#define KMAP_KERNEL_ONLY 0x10

// Export POSIX names for user code.
#if !__APOS_BUILDING_KERNEL__
# define PROT_NONE KPROT_NONE
# define PROT_READ KPROT_READ
# define PROT_WRITE KPROT_WRITE
# define PROT_EXEC KPROT_EXEC
# define MAP_SHARED KMAP_SHARED
# define MAP_PRIVATE KMAP_PRIVATE
# define MAP_FIXED KMAP_FIXED
# define MAP_ANONYMOUS KMAP_ANONYMOUS
#endif

#endif
