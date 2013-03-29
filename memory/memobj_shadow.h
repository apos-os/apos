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

// A shadow memobj represents a copy-on-write copy of another underlying memobj.
// For pages that are only read, the shadow memobj will share pages with the
// underlying object.  Pages that are written to will be copied.
//
// Only one vm_area in one process should use a particular shadow memobj (i.e.,
// it must not be shared).  Otherwise, the copy-on-write mappings may not be
// propagated to all existing mappings in other areas or processes.
#ifndef APOO_MEMORY_MEMOBJ_SHADOW_H
#define APOO_MEMORY_MEMOBJ_SHADOW_H

#include "memory/memobj.h"

// Initialize a shadow memobj in shadow_memobj shadowing sub_obj.
void memobj_create_shadow(memobj_t* sub_obj, memobj_t* shadow_memobj);

#endif
