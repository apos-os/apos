// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_CORE_LOADER_ELF64_H
#define APOO_OS_CORE_LOADER_ELF64_H

#include "proc/load/elf-internal.h"

// Checks the validity of an Elf64_Ehdr.  Returns 0 if it's valid (i.e., we can
// load the file with that header).
int elf64_check_header(const Elf64_Ehdr* header);

#endif
