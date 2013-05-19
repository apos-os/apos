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

#ifndef APOO_MEMORY_VM_AREA_H
#define APOO_MEMORY_VM_AREA_H

#include "common/list.h"
#include "common/types.h"
#include "memory/flags.h"
#include "memory/memobj.h"
#include "memory/block_cache.h"
#include "proc/process.h"

// A vm_area_t represents a mapped region of virtual memory in a process.  Each
// is backed by a memobj_t.
//
// NOTE: if you modify this structure, be sure to update vm_area_create() and
// vm_fork_address_space_into() to handle the new field.
struct vm_area {
  // The memobj_t backing the region.  The vm_area holds one reference on the
  // memobj_t.
  //
  // This may be NULL for certain anonymous kernel mappings that must exists
  // early in the boot process (e.g., the heap).
  memobj_t* memobj;

  // If set, allow new pages to be allocated for this area.
  int allow_allocation;
  int is_private;

  // The address and length (in bytes) of the region in the process's address
  // space.  Must be page-aligned and page-sized.
  //
  // If (flags & MEM_GLOBAL), additional restrictions may apply.
  addr_t vm_base;
  addr_t vm_length;

  // Offset (in bytes) within the memobj.
  addr_t memobj_base;

  // Protection, access, and other flags.
  int prot;
  mem_access_t access;
  int flags;

  // Parent process.
  process_t* proc;

  // Link to the next vm_area in this process.
  list_link_t vm_proc_list;

  // TODO(aoates): implement swapping so we don't have to pin the resident
  // pages.  Then we can ditch this array.
  // An array of (vm_length / PAGE_SIZE) bc_entry_t's, one for each page in the
  // vm_area_t.  If the page is resident, this will point to the (pinned)
  // bc_entry_t; otherwise, it will be NULL.
  //
  // This may not exist if memobj == NULL.
  bc_entry_t* pages[];
};
typedef struct vm_area vm_area_t;

// Create a vm_area_t of the given size.
int vm_area_create(addr_t length, vm_area_t** area_out);

#endif
