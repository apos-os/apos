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

// Code for loading ELF binaries.
#ifndef APOO_PROC_LOAD_ELF_H
#define APOO_PROC_LOAD_ELF_H

#include "proc/load/load.h"

// Attempts to detect if the given binary is ELF.
// TODO(aoates): combine elf and elf64 code since it's essentially duplicated.
int elf_is_loadable(int fd);
int elf64_is_loadable(int fd);

// Load a binary from the given fd.  Returns 0 on success, or -errno.
//
// REQUIRES: elf_is_loadable(fd) == 0.
int elf_load(int fd, load_binary_t** binary_out);
int elf64_load(int fd, load_binary_t** binary_out);

#endif
