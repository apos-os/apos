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

#include <stddef.h>

#include "common/errno.h"
#include "proc/load/elf.h"
#include "proc/load/load.h"
#include "proc/load/load-internal.h"

static load_module_t g_modules[] = {
  { &elf_is_loadable, &elf_load },
  { NULL, NULL },
};

int load_binary(int fd, load_binary_t** binary_out) {
  for (int module_idx = 0; g_modules[module_idx].is_loadable != NULL;
       ++module_idx) {
    int result = g_modules[module_idx].is_loadable(fd);
    if (result == 0) {
      return g_modules[module_idx].load(fd, binary_out);
    }
  }

  // TODO(aoates): verify the loaded binary (i.e. to make sure all the mappings
  // are valid, don't overlap, etc).

  return -ENOTSUP;
}
