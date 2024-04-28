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

#ifndef APOO_MAIN_KERNEL_H
#define APOO_MAIN_KERNEL_H

#include "dev/devicetree/devicetree.h"
#include "memory/memory.h"

typedef struct {
  memory_info_t* meminfo;  // Required.

  // The device tree if present, or NULL.
  const dt_tree_t* dtree;

  // Tokenized command line string, NULL-terminated.
  const char** cmd_line;
} boot_info_t;

void kmain(boot_info_t* boot, const char* cmdline);

const boot_info_t* get_boot_info(void);

#endif
