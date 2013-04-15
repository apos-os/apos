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

#include "common/types.h"
#include "memory/vm_area.h"
#include "proc/process.h"

// Find an address in the process's vm map with a hole at least as large as the
// requested size, between start_addr and end_addr.  If no such holes are
// available, returns  0.
addr_t vm_find_hole(process_t* proc, addr_t start_addr, addr_t end_addr,
                    addr_t length);

// Insert the given vm_area_t into the process's memory map.  The new area MUST
// NOT overlap with any existing area.
void vm_insert_area(process_t* proc, vm_area_t* area);

// Verify that accesses of the given type are valid for the entire region
// [start, end).  Returns 0 if the access is valid, -EFAULT if not.
// TODO(aoates): should we use vm_fault_op_t, etc here?
int vm_verify_region(process_t* proc, addr_t start, addr_t end,
                     int is_write, int is_user);
#endif
