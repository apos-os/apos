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

#include "arch/memory/page_map.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "memory/mmap.h"
#include "memory/memory.h"
#include "memory/memobj.h"
#include "memory/memobj_anon.h"
#include "memory/memobj_shadow.h"
#include "memory/vm.h"
#include "memory/vm_area.h"
#include "proc/process.h"
#include "vfs/vfs.h"

// Unmap a portion of the given vm_area_t.  Zero, one, or two smaller vm_area_ts
// may be created (and added to the process's list), depending on the overlap of
// the unmap region and the vm_area_t.
static int unmap_area(vm_area_t* area, addr_t unmap_start, addr_t unmap_end) {
  KASSERT(unmap_start >= area->vm_base);
  KASSERT(unmap_end <= area->vm_base + area->vm_length);

  // Split the area into 3 logical regions: the prefix region, the unmap region,
  // and the suffix region.  The prefix and/or suffix regions may be empty.
  const addr_t prefix_start = area->vm_base;
  const addr_t prefix_end = unmap_start;
  const addr_t suffix_start = unmap_end;
  const addr_t suffix_end = area->vm_base + area->vm_length;

  // Resize the current vm_area_t into the prefix or suffix, and optionally
  // create a new area for the suffix.
  addr_t resize_start = 0, resize_end = 0;
  addr_t new_area_start = 0, new_area_end = 0;
  if (prefix_end > prefix_start) {
    resize_start = prefix_start;
    resize_end = prefix_end;
    new_area_start = suffix_start;
    new_area_end = suffix_end;
  } else {
    resize_start = suffix_start;
    resize_end = suffix_end;
  }

  KASSERT((resize_end - resize_start) + (new_area_end - new_area_start) +
          (unmap_end - unmap_start) == area->vm_length);

  // Create the new area, if necessary.
  vm_area_t* new_area = 0x0;
  if (new_area_end > new_area_start) {
    KASSERT(new_area_start >= area->vm_base);
    KASSERT(new_area_end <= area->vm_base + area->vm_length);
    const int result = vm_area_create(new_area_end - new_area_start,
                                      /*needs_pages=*/true, &new_area);
    if (result) return result;

    new_area->memobj = area->memobj;
    new_area->memobj->ops->ref(new_area->memobj);
    new_area->allow_allocation = area->allow_allocation;
    new_area->is_private = area->is_private;
    new_area->vm_base = new_area_start;
    new_area->vm_length = new_area_end - new_area_start;
    new_area->memobj_base =
        area->memobj_base + (new_area_start - area->vm_base);
    new_area->prot = area->prot;
    new_area->access = area->access;
    new_area->flags = area->flags;
    new_area->proc = area->proc;

    // Transfer page entries from the old area to the new one.
    const addr_t new_area_pages = new_area->vm_length / PAGE_SIZE;
    const addr_t new_area_pages_offset =
        (new_area_start - area->vm_base) / PAGE_SIZE;
    for (unsigned int page_idx = 0; page_idx < new_area_pages; ++page_idx) {
      KASSERT_DBG(new_area->pages[page_idx] == NULL);
      new_area->pages[page_idx] = area->pages[new_area_pages_offset + page_idx];
      area->pages[new_area_pages_offset + page_idx] = 0x0;
    }
  }

  // Unmap the portion of the original area.
  for (unsigned int page_idx = 0;
       page_idx < (unmap_end - unmap_start) / PAGE_SIZE;
       page_idx++) {
    const addr_t area_page_idx =
        (unmap_start - area->vm_base) / PAGE_SIZE + page_idx;
    if (area->pages[area_page_idx]) {
      // TODO(aoates): what if this blocks?  It shouldn't, but that's not
      // guaranteed by the interface.
      // TODO(aoates): only flush if the page is dirty.
      // TODO(aoates): do we want this to be sync or async?
      area->memobj->ops->put_page(area->memobj, area->pages[area_page_idx],
                                  BC_FLUSH_SYNC);
      area->pages[area_page_idx] = 0x0;
      page_frame_unmap_virtual(area->vm_base + (area_page_idx * PAGE_SIZE));
    }
  }

  // Resize or remove the original mapping.
  if (resize_end > resize_start) {
    KASSERT(resize_start >= area->vm_base);
    const addr_t orig_base = area->vm_base;
    area->vm_base = resize_start;
    area->vm_length = resize_end - resize_start;
    area->memobj_base += resize_start - orig_base;

    if (new_area) {
      KASSERT(new_area->vm_base >= area->vm_base + area->vm_length);
      list_insert(&area->proc->vm_area_list, &area->vm_proc_list,
                  &new_area->vm_proc_list);
    }
  } else {
    KASSERT(unmap_start == area->vm_base);
    KASSERT(unmap_end == area->vm_base + area->vm_length);
    list_remove(&area->proc->vm_area_list, &area->vm_proc_list);
    vm_area_destroy(area);
  }

  return 0;
}

int do_mmap(void* addr, addr_t length, int prot, int flags,
            int fd, addr_t offset, void** addr_out) {
  if ((!(flags & KMAP_PRIVATE) && !(flags & KMAP_SHARED)) ||
      ((flags & KMAP_PRIVATE) && (flags & KMAP_SHARED))) {
    return -EINVAL;
  }
  if (length == 0 || length % PAGE_SIZE != 0 || offset % PAGE_SIZE != 0) {
    return -EINVAL;
  }
  if (flags & ~(KMAP_SHARED | KMAP_PRIVATE | KMAP_FIXED | KMAP_ANONYMOUS)) {
    return -EINVAL;
  }

  if ((addr_t)addr > MEM_LAST_USER_MAPPABLE_ADDR - length + 1) {
    return -EINVAL;
  }

  // Check address space limits.
  const apos_rlim_t limit = proc_current()->limits[APOS_RLIMIT_AS].rlim_cur;
  if (limit != APOS_RLIM_INFINITY) {
    size_t total_as = mmap_get_usage();
    if (total_as + length > limit) {
      return -ENOMEM;
    }
  }

  // Find an appropriate address.
  addr_t hole_addr = 0x0;
  if (flags & KMAP_FIXED) {
    if ((addr_t)addr % PAGE_SIZE != 0) {
      return -EINVAL;
    }

    // Unmap anything overlapping the requested region.
    const int result = do_munmap(addr, length);
    if (result) return result;
    hole_addr = (addr_t)addr;
  } else {
    hole_addr =
        vm_find_hole(proc_current(),
                     max(addr2page((addr_t)addr),
                         (addr_t)MEM_FIRST_MAPPABLE_ADDR),
                     MEM_LAST_USER_MAPPABLE_ADDR + 1,
                     length);
  }
  if (hole_addr == 0) {
    return -ENOMEM;
  }

  // Get the underlying memobj.
  memobj_t* memobj = 0x0;
  int result;
  if (flags & KMAP_ANONYMOUS) {
    // Note that it doesn't matter if it's private or shared.
    // TODO(aoates): allow anonymous mappings to share read-only pages of
    // zeroes, and only create new ones on writes.
    memobj = memobj_create_anon();
    if (!memobj) return -ENOMEM;
  } else {
    kmode_t fd_mode = 0;
    // If the mapping is private, we only need read access to the file.
    if (flags & KMAP_PRIVATE) {
      fd_mode = VFS_O_RDONLY;
    } else {
      if ((prot & KPROT_READ) && (prot & KPROT_WRITE)) fd_mode = VFS_O_RDWR;
      else if (prot & KPROT_READ) fd_mode = VFS_O_RDONLY;
      else if (prot & KPROT_WRITE) fd_mode = VFS_O_WRONLY;
    }
    result = vfs_get_memobj(fd, fd_mode, &memobj);
    if (result) return result;

    // For private mappings, create a shadow object.
    if (flags & KMAP_PRIVATE) {
      memobj_t* shadow_obj = memobj_create_shadow(memobj);
      memobj->ops->unref(memobj);  // Don't need the parent.
      memobj = shadow_obj;
    }
  }

  // Create the new vm_area_t.
  vm_area_t* area = 0x0;
  result = vm_area_create(length, /*needs_pages=*/true, &area);
  if (result) return result;

  // TODO(aoates): check against length of file

  area->memobj = memobj;
  area->allow_allocation = true;
  area->is_private = (flags & KMAP_PRIVATE);
  area->vm_base = hole_addr;
  area->vm_length = length;
  area->memobj_base = offset;
  area->prot = prot;
  area->access = MEM_ACCESS_KERNEL_AND_USER;
  area->flags = 0x0;

  area->proc = proc_current();
  vm_insert_area(proc_current(), area);
  *addr_out = (void*)area->vm_base;
  return 0;
}

int do_munmap(void* addr_ptr, addr_t length) {
  const addr_t addr = (addr_t)addr_ptr;
  if (addr % PAGE_SIZE != 0 || length % PAGE_SIZE != 0) {
    return -EINVAL;
  }

  if ((addr_t)addr > MEM_LAST_USER_MAPPABLE_ADDR - length + 1) {
    return -EINVAL;
  }

  list_link_t* link = proc_current()->vm_area_list.head;
  while (link && addr <= MEM_LAST_USER_MAPPABLE_ADDR) {
    vm_area_t* area = container_of(link, vm_area_t, vm_proc_list);
    list_link_t* next = link->next;
    const addr_t overlap_start = max(addr, area->vm_base);
    const addr_t overlap_end =
        min(addr + length, area->vm_base + area->vm_length);
    if (overlap_end > overlap_start) {
      KASSERT(area->access == MEM_ACCESS_KERNEL_AND_USER);
      unmap_area(area, overlap_start, overlap_end);
      // area may no longer be valid.
    }
    link = next;
  }

  return 0;
}

size_t mmap_get_usage(void) {
  list_link_t* link = proc_current()->vm_area_list.head;
  addrdiff_t total_as = 0;
  while (link) {
    const vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    if (area->access == MEM_ACCESS_KERNEL_AND_USER) {
      total_as += area->vm_length;
    }
    link = link->next;
  }
  return (size_t)total_as;
}
