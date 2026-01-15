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

#ifndef APOO_OS_CORE_LOADER_LD_ALLOC_H
#define APOO_OS_CORE_LOADER_LD_ALLOC_H

#include <stddef.h>

// Simple bump allocator for use in the loader.
// TODO(aoates): enhance this so we can free most memory once loading is done.
void* ld_alloc(size_t len);

#define LD_ALLOC(type) ((type*)ld_alloc(sizeof(type)))

#endif
