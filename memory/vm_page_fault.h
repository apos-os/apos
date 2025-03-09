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

#ifndef APOO_MEMORY_VM_PAGE_FAULT_H
#define APOO_MEMORY_VM_PAGE_FAULT_H

#include "common/types.h"

typedef enum {
  // The fault was caused by a missing page.
  VM_FAULT_NOT_PRESENT,

  // The fault was caused by an access violation.
  VM_FAULT_ACCESS,
} vm_fault_type_t;

// The operation that caused the fault.
typedef enum {
  VM_FAULT_READ,
  VM_FAULT_WRITE,
} vm_fault_op_t;

// What mode triggered the fault.
typedef enum {
  VM_FAULT_KERNEL,
  VM_FAULT_USER,
} vm_fault_mode_t;

// Handle a page fault at the given address.  If the fault can't be handled
// (it's an invalid access, the backing data can't be paged in, etc) then an
// appropriate signal is generated on the current process and an error code is
// returned.
int vm_handle_page_fault(addr_t address, vm_fault_type_t type, vm_fault_op_t op,
                         vm_fault_mode_t mode);

// As above, but called with the current process already locked.
int vm_handle_page_fault_locked(addr_t address, vm_fault_type_t type,
                                vm_fault_op_t op, vm_fault_mode_t mode);

#endif
