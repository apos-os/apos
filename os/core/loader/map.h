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

#ifndef APOO_OS_CORE_LOADER_MAP_H
#define APOO_OS_CORE_LOADER_MAP_H

#include "os/core/loader/load-binary.h"

#define PAGE_SIZE 4096  // TODO(aoates): learn this dynamically.

// mmap the given binary in.
int load_map_binary(int fd, const load_binary_t* binary);

#endif
