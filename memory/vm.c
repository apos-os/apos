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

#include "arch/memory/page_alloc.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/list.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/memobj_shadow.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/process.h"

addr_t vm_find_hole(process_t* proc, addr_t start_addr, addr_t end_addr,
                    addr_t length) {
  addr_t addr = start_addr;
  list_link_t* link = proc->vm_area_list.head;
  while (link && addr < end_addr) {
    const vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    if (addr < area->vm_base) {
      const addr_t hole_size = min(area->vm_base, end_addr) - addr;
      if (hole_size >= length) {
        return addr;
      }
    }
    addr = area->vm_base + area->vm_length;
    link = link->next;
  }

  if (addr >= end_addr || (end_addr - addr) < length) {
    return 0;
  } else {
    return addr;
  }
}

void vm_insert_area(process_t* proc, vm_area_t* area) {
  KASSERT(!list_link_on_list(&proc->vm_area_list, &area->vm_proc_list));
  list_link_t* prev = 0x0;
  list_link_t* curr = proc->vm_area_list.head;
  while (curr) {
    vm_area_t* curr_area = container_of(curr, vm_area_t, vm_proc_list);
    if (curr_area->vm_base > area->vm_base) {
      KASSERT(area->vm_base + area->vm_length <= curr_area->vm_base);
      break;
    }
    prev = curr;
    curr = curr->next;
  }
  if (prev) {
    vm_area_t* prev_area = container_of(prev, vm_area_t, vm_proc_list);
    KASSERT(prev_area->vm_base + prev_area->vm_length <= area->vm_base);
  }
  list_insert(&proc->vm_area_list, prev, &area->vm_proc_list);
}

// Check if access is allowed to the given region.
// TODO(aoates): unify this with fault_allowed() in vm_page_fault.c
static int verify_access(vm_area_t* area, bool is_write, bool is_user) {
  if (is_write && (!(area->prot & MEM_PROT_WRITE)))
    return -EFAULT;
  if (is_user && (area->access != MEM_ACCESS_KERNEL_AND_USER))
    return -EFAULT;
  return 0;
}

int vm_verify_region(process_t* proc, addr_t start, addr_t end,
                     bool is_write, bool is_user) {
  if (!proc || start >= end) {
    return -EINVAL;
  }

  list_link_t* link = proc->vm_area_list.head;
  while (link && start < end) {
    vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    const addr_t overlap_start = max(area->vm_base, start);
    const addr_t overlap_end =
        max(overlap_start, min(area->vm_base + area->vm_length, end));
    if (area->vm_base > end) {
      break;
    } else if (area->vm_base > start) {
      return -EFAULT;
    } else if (overlap_start < overlap_end) {
      const int result = verify_access(area, is_write, is_user);
      if (result) return result;
    }
    start = overlap_end;
    link = link->next;
  }

  if (start < end) {
    return -EFAULT;
  } else {
    return 0;
  }
}

int vm_verify_address(process_t* proc, addr_t addr, bool is_write,
                      bool is_user, addr_t* end_out) {
  if (!proc || !end_out) {
    return -EINVAL;
  }
  *end_out = addr;

  // First, find the region containing addr.
  vm_area_t* addr_area = NULL;
  list_link_t* link = proc->vm_area_list.head;
  while (link) {
    vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    if (addr >= area->vm_base && addr < area->vm_base + area->vm_length) {
      addr_area = area;
      break;
    }
    link = link->next;
  }

  if (!addr_area) {
    return -EFAULT;
  }

  // Check if the access is valid.
  int access_valid = verify_access(addr_area, is_write, is_user);
  if (access_valid != 0) {
    return access_valid;
  }

  // Find the largest contiguous usable region.
  vm_area_t* prev_area = NULL;
  vm_area_t* contig_area = addr_area;
  link = &contig_area->vm_proc_list;
  do {
    *end_out = contig_area->vm_base + contig_area->vm_length;
    prev_area = contig_area;
    link = link->next;
    contig_area = container_of(link, vm_area_t, vm_proc_list);
  } while (link &&
           contig_area->vm_base == prev_area->vm_base + prev_area->vm_length &&
           verify_access(contig_area, is_write, is_user) == 0);
  return 0;
}

void vm_create_kernel_mapping(vm_area_t* area, addr_t base, addr_t length,
                              bool allow_allocation) {
  KASSERT(proc_current() != 0x0);
  KASSERT(proc_current()->id == 0);

  kmemset(area, 0, sizeof(vm_area_t));
  area->memobj = 0x0;
  area->allow_allocation = allow_allocation;
  area->is_private = false;
  area->vm_base = base;
  area->vm_length = length;
  area->prot = MEM_PROT_ALL;
  area->access = MEM_ACCESS_KERNEL_ONLY;
  area->flags = MEM_GLOBAL;
  area->proc = proc_current();
  area->vm_proc_list = LIST_LINK_INIT;

  vm_insert_area(proc_current(), area);

  page_frame_init_global_mapping(base, length);
}

int vm_fork_address_space_into(process_t* target_proc) {
  KASSERT(list_empty(&target_proc->vm_area_list));

  list_link_t* link = proc_current()->vm_area_list.head;
  while (link) {
    vm_area_t* const source_area = container_of(link, vm_area_t, vm_proc_list);
    vm_area_t* target_area = NULL;
    const int result = vm_area_create(source_area->vm_length, &target_area);
    if (result) return result;

    target_area->allow_allocation = source_area->allow_allocation;
    target_area->is_private = source_area->is_private;
    target_area->vm_base = source_area->vm_base;
    target_area->vm_length = source_area->vm_length;
    target_area->memobj_base = source_area->memobj_base;
    target_area->prot = source_area->prot;
    target_area->access = source_area->access;
    target_area->flags = source_area->flags;
    target_area->proc = target_proc;

    // If the mapping is private, create shadow objects in both processes.
    if (source_area->memobj) {
      if (target_area->is_private) {
        memobj_t* orig_memobj = source_area->memobj;
        source_area->memobj = memobj_create_shadow(orig_memobj);
        target_area->memobj = memobj_create_shadow(orig_memobj);

        source_area->memobj->ops->ref(source_area->memobj);
        target_area->memobj->ops->ref(target_area->memobj);

        // Unmap the range in our current process so we pick up the COW versions.
        // TODO(aoates): just make the current mappings read-only.
        page_frame_unmap_virtual_range(
            source_area->vm_base, source_area->vm_length);
      } else {
        target_area->memobj = source_area->memobj;
        target_area->memobj->ops->ref(target_area->memobj);
      }
    } else {
      KASSERT(target_area->flags & MEM_GLOBAL);
      target_area->memobj = 0x0;
    }

    // If it's a global mapping, link it in the new address space.
    if (target_area->flags & MEM_GLOBAL) {
      page_frame_link_global_mapping(target_proc->page_directory,
                                     target_area->vm_base,
                                     target_area->vm_length);
    }

    // TODO(aoates): this is O(n^2), but has some nice sanity checks.
    vm_insert_area(target_proc, target_area);

    link = link->next;
  }

  return 0;
}
