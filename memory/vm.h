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

#ifndef APOO_MEMORY_VM_H
#define APOO_MEMORY_VM_H

#include "memory/vm_area.h"
#include "proc/process.h"

// Insert the given vm_area_t into the process's memory map.  The new area MUST
// NOT overlap with any existing area.
void vm_insert_area(process_t* proc, vm_area_t* area);

#endif
