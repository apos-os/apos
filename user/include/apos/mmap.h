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
#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

// Exactly one of MAP_SHARED and MAP_PRIVATE must be given.
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02

// Other flags.
#define MAP_FIXED 0x04
#define MAP_ANONYMOUS 0x08

#endif
