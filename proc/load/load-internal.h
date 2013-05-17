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

#endif
