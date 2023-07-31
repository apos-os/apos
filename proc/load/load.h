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

// Architecture of a binary.  A particular kernel architecture may support
// multiple binary architectures (e.g. x86-64 supports both 32- and 64-bit x86
// binaries).
typedef enum {
  BIN_NONE = 0,
  BIN_X86_32,
  BIN_RISCV_64,
} bin_arch_t;

// A region to load into memory.  It consists of a portion to load from a file,
// followed by a portion to be anonymously mapped, either of which may be
// zero-length.  The address and length do not have to be page-aligned (but see
// additional restrictions below).
//
// If mem_len > file_len, the portion after the file data will be filled with
// zeroes.
//
//                +------------------------+
// <@file_offset> | ABC...                 |
//                +------------------------+
//                            |
//                       +----+
//                       V
//           +------------------------+-----------------+
// <@vaddr>  | ABC...                 | 000...          |
//           +------------------------|-----------------+
//           | <----- file_len -----> |
//           | <--------------- mem_len --------------> |
//
// REQUIRES: file_offset == vaddr (mod PAGE_SIZE)
// REQUIRES: mem_len >= file_len
typedef struct {
  addr_t file_offset;  // Offset within the file.  Unspecified if file_len == 0.
  addr_t vaddr;  // Virtual address to load at.  Unspecified if mem_len == 0.
  addr_t file_len;  // Number of bytes to map from the file.
  addr_t mem_len;  // Number of bytes to map into memory.  Must be >= file_len.

  // Protection flags (from memory/flags.h).
  int prot;
} load_region_t;

// A set of mappings corresponding to a single loadable binary.
//
// The mappings do not have to start and end on page boundaries, but they must
// not overlap on the same page.
typedef struct {
  bin_arch_t arch;  // The architecture of the binary.
  addr_t entry;  // The binary's entry point, or 0x0 if none.
  int num_regions;  // How many regions to load;
  load_region_t regions[];  // num_regions load_region_ts.
} load_binary_t;

// Attempt to load a binary from the given fd.  Allocates a load_binary_t in
// binary_out if successful (and returns 0).
//
// If successful, the caller MUST kfree(*binary_out) when it's done with it.
int load_binary(int fd, load_binary_t** binary_out);

// Attempt to map the given binary into the current address space.
//
// Note: does NOT tear down any existing mappings; the caller should almost
// certainly do that before calling this.
int load_map_binary(int fd, const load_binary_t* binary);

#endif
