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

// Code for loading binaries into memory.
#ifndef APOO_PROC_LOAD_LOAD_H
#define APOO_PROC_LOAD_LOAD_H

#include "common/types.h"
#include "memory/flags.h"

// A region to load into memory.  It consists of a portion to load from a file,
// followed by a portion to be anonymously mapped, either of which may be
// zero-length.  The address and length do not have to be page-aligned (but see
// additional restrictions below).
//
//                +------------------------+
// <@file_offset> | ABC...                 |
//                +------------------------+
//                            |
//                       +----+
//                       V
//           +------------------------+-----------------+
// <@vaddr>  | ABC...<file_len>       | 000...<mem_len> |
//           +------------------------|-----------------+
//
// REQUIRES: file_offset == vaddr (mod PAGE_SIZE)
typedef struct {
  addr_t file_offset;  // Offset within the file.
  addr_t vaddr;  // Virtual address to load at.
  addr_t file_len;  // Number of bytes to load from the file.
  addr_t mem_len;  // Number of bytes to map anonymously after the file portion.

  // Protection flags (from memory/flags.h).
  int prot;
} load_region_t;

// A set of mappings corresponding to a single loadable binary.
//
// The mappings do not have to start and end on page boundaries, but they must
// not overlap on the same page.
typedef struct {
  addr_t entry;  // The binary's entry point, or 0x0 if none.
  int num_regions;  // How many regions to load;
  load_region_t regions[];  // num_regions load_region_ts.
} load_binary_t;

// Attempt to load a binary from the given fd.  Allocates a load_binary_t in
// binary_out if successful (and returns 0).
//
// If successful, the caller MUST kfree(*binary_out) when it's done with it.
int load_binary(int fd, load_binary_t** binary_out);

#endif
