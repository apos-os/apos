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

#ifndef APOO_MEMORY_MEMOBJ_BLOCK_DEV_H
#define APOO_MEMORY_MEMOBJ_BLOCK_DEV_H

#include "memory/memobj.h"
#include "user/include/apos/dev.h"

// Create a memory object backed by a block device.  Only one memobj_t should be
// created per device.
int memobj_create_block_dev(memobj_t* obj, apos_dev_t dev);

#endif
