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

#ifndef APOO_PROC_LOAD_LOAD_INTERNAL_H
#define APOO_PROC_LOAD_LOAD_INTERNAL_H

#include "proc/load/load.h"

// Interface for a loader module.  Each function operates on a file descriptor,
// which must be readable.
//
// The loader module will not write to the fd, but may seek within it.
typedef struct {
  // Returns 0 if the given binary is loadable by this module, -ENOTSUP if not,
  // or another error code.
  int (*is_loadable)(int fd);

  // Load a binary from the given fd.  Returns 0 on success, or -errno.
  //
  // REQUIRES: is_loadable(fd) == 0.
  int (*load)(int fd, load_binary_t** binary_out);
} load_module_t;

// Given a hybrid file/memory load_region_t, that is not page-aligned, split it
// into up to 3 regions.  Each region will be page-aligned, and all but the last
// non-empty region will be page-sized.
//
// The first region will consist only of file data, and will be 0 or more pages
// in length.  The middle region will have both file data and memory data (which
// must be zeroed), and will be up to 1 pages in length.  The third region will
// be only memory data (i.e., an anonymous mapping), and will be 0 or more pages
// in length.
//
// Any of the three regions may have mem_length == 0.
void load_pagify_region(const load_region_t* orig_region,
                        load_region_t* region0,
                        load_region_t* region1,
                        load_region_t* region2);

#endif
