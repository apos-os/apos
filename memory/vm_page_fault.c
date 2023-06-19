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
#include "arch/memory/page_map.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/list.h"
#include "common/types.h"
#include "memory/flags.h"
#include "memory/memory.h"
#include "memory/vm_page_fault.h"
#include "memory/vm_area.h"
#include "proc/process.h"
#include "proc/signal/signal.h"

#define KLOG(...) klogfm(KL_PAGE_FAULT, __VA_ARGS__)

static inline vm_area_t* link2area(list_link_t* link) {
  return container_of(link, vm_area_t, vm_proc_list);
}

static void check_vm_list(process_t* proc) {
  list_link_t* link = proc->vm_area_list.head;
  while (link) {
    vm_area_t* const area = link2area(link);
    KASSERT(area->vm_base >= MEM_FIRST_MAPPABLE_ADDR);
    KASSERT(area->vm_length > 0);
    KASSERT(MEM_LAST_MAPPABLE_ADDR - area->vm_base >= area->vm_length);
    KASSERT(area->vm_base % PAGE_SIZE == 0);
    KASSERT(area->vm_length % PAGE_SIZE == 0);
    KASSERT(area->memobj_base % PAGE_SIZE == 0);
    if (link->prev) {
      vm_area_t* const prev_area = link2area(link->prev);
      KASSERT(area->vm_base > prev_area->vm_base);
      KASSERT(area->vm_base >= prev_area->vm_base + prev_area->vm_length);
    }
    link = link->next;
  }
}

static vm_area_t* find_area(process_t* proc, addr_t address) {
  list_link_t* link = proc->vm_area_list.head;
  while (link) {
    vm_area_t* const area = container_of(link, vm_area_t, vm_proc_list);
    if (address >= area->vm_base && address < area->vm_base + area->vm_length) {
      return area;
    }
    link = link->next;
  }
  return 0x0;
}

static int fault_allowed(vm_area_t* area, vm_fault_type_t type,
                          vm_fault_op_t op, vm_fault_mode_t mode) {
  if (!area) {
    KLOG(INFO, "address not in any mapped region\n");
    return 0;
  }
  if (type == VM_FAULT_NOT_PRESENT && !area->allow_allocation) {
    KLOG(INFO, "cannot allocate new pages in the mapped region\n");
    return 0;
  }
  switch (op) {
    case VM_FAULT_READ:
      if (!(area->prot & MEM_PROT_READ)) {
        KLOG(INFO, "read operation not allowed in mapped region\n");
        return 0;
      }
      break;

    case VM_FAULT_WRITE:
      if (!(area->prot & MEM_PROT_WRITE)) {
        KLOG(INFO, "write operation not allowed in mapped region\n");
        return 0;
      }
      break;
  }
  if (mode == VM_FAULT_USER && area->access != MEM_ACCESS_KERNEL_AND_USER) {
    KLOG(WARNING, "user mode attempt to access kernel memory\n");
    return 0;
  }
  return 1;
}

int vm_handle_page_fault(addr_t address, vm_fault_type_t type, vm_fault_op_t op,
                         vm_fault_mode_t mode) {
  process_t* proc = proc_current();
  if (ENABLE_KERNEL_SAFETY_NETS) {
    check_vm_list(proc);
  }

  // Find the vm_area containing the address.
  vm_area_t* area = find_area(proc, address);
  if (!fault_allowed(area, type, op, mode)) {
    switch (mode) {
      case VM_FAULT_KERNEL:
        KLOG(ERROR, "kernel page fault: addr: 0x%" PRIxADDR "\n", address);
        die("unhandled kernel page fault");
        break;

      case VM_FAULT_USER:
        KLOG(INFO, "SIGSEGV: bad access to address %#" PRIxADDR " (pid %d)\n",
             address, proc->id);
        KASSERT(proc_force_signal_on_thread(
                proc_current(), kthread_current_thread(), SIGSEGV) == 0);
        return -EACCES;
    }
  }

  phys_addr_t phys_addr = 0x0;
  const addr_t virt_page = addr2page(address);

  // Some kernel mappings (such as the heap) don't have a backing memobj.
  if (!area->memobj) {
    KASSERT(area->access == MEM_ACCESS_KERNEL_ONLY);
    KASSERT(mode == VM_FAULT_KERNEL);

    // TODO(aoates): if no pages are available, force a swap.
    phys_addr = page_frame_alloc();
    KASSERT(phys_addr);
  } else {
    KASSERT_DBG(virt_page >= area->vm_base &&
                virt_page < area->vm_base + area->vm_length);
    const addr_t area_page_offset = (virt_page - area->vm_base) / PAGE_SIZE;
    if (type == VM_FAULT_ACCESS || area->pages[area_page_offset] == 0x0) {
      if (area->pages[area_page_offset] != 0x0) {
        // TODO(aoates): verify the page isn't dirty.
        // ASSERT(current_mapping not writable)
        area->memobj->ops->put_page(area->memobj, area->pages[area_page_offset],
                                    BC_FLUSH_NONE);
        area->pages[area_page_offset] = 0x0;
      }

      const int result = area->memobj->ops->get_page(
          area->memobj,
          (area->memobj_base / PAGE_SIZE) + area_page_offset,
          op == VM_FAULT_WRITE,
          &area->pages[area_page_offset]);
      if (result) {
        switch (mode) {
          case VM_FAULT_KERNEL:
            KLOG(ERROR, "kernel mode SIGBUS: addr: 0x%" PRIxADDR " error: %s\n",
                 address, errorname(-result));
            die("failed kernel page fault");
            break;

          case VM_FAULT_USER:
            KLOG(INFO,
                 "SIGBUS: unable to access address %#" PRIxADDR
                 " (pid %d, error=%s)\n",
                 address, proc->id, errorname(-result));
            KASSERT(proc_force_signal_on_thread(
                        proc_current(), kthread_current_thread(), SIGBUS) == 0);
            // TODO(aoates): write a test that catches if this unmap is missing.
            page_frame_unmap_virtual(virt_page);
            return result;
        }
      }
    }
    KASSERT(area->pages[area_page_offset]);
    phys_addr = area->pages[area_page_offset]->block_phys;
  }

  // Only create a writable mapping if the operation is a write (so that we can
  // do copy-on-write).
  const int mapping_prot = (MEM_PROT_READ | MEM_PROT_EXEC |
          (op == VM_FAULT_WRITE ? MEM_PROT_WRITE : 0x0));

  KASSERT(phys_addr != 0x0);
  page_frame_map_virtual(virt_page, phys_addr,
                         mapping_prot, area->access, area->flags);
  return 0;
}
