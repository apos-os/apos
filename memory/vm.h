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

#include <stdbool.h>

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
int vm_verify_region(process_t* proc, addr_t start, addr_t end, bool is_write,
                     bool is_user);

// Verifies that an access to the given address is valid, as for
// vm_verify_region.  Returns (in end_out) the next *invalid* address after this
// one for this type of access.
//
// That is, *end_out is the highest address greater than addr s.t.
// vm_verify_region(addr, end_out, ...) == 0.
//
// Returns 0 if the access is valid, -EFAULT (and sets *end_out to addr) if not.
int vm_verify_address(process_t* proc, addr_t addr, bool is_write, bool is_user,
                      addr_t* end_out);

// Initialize and insert a global kernel memory region (such as the heap, or the
// linearly-mapped kernel binary).
//
// If allow_allocation is true, then non-present page faults in the region will
// cause a new anonymous page to be allocated and mapped.
//
// If allow_allocation is false, then non-present page faults in the region will
// be fatal.  It is the callers responsibility to create the needed mappings by
// calling page_frame_map_virtual() directly.
//
// REQUIRES: proc_current() is the root process.
void vm_create_kernel_mapping(vm_area_t* area, addr_t base, addr_t length,
                              bool allow_allocation);

// Fork the current process's address space and mappings into another process.
// Each vm_area_t in the current process will be copied to the new process.  If
// the area represents a private mapping, shadow objects will be created for
// both the current process and new process to ensure they don't share
// modifications.
//
// For any global mappings, links the new address space to the global region.
//
// Returns 0 on success, or -errno on error (in which case the target's
// vm_area_list is left in an indeterminate state).
int vm_fork_address_space_into(process_t* target);

#endif
