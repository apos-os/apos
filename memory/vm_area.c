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

#include <stdint.h>

#include "common/errno.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "memory/memory.h"
#include "memory/vm_area.h"

int vm_area_create(addr_t length, vm_area_t** area_out) {
  *area_out = 0x0;
  if (length % PAGE_SIZE != 0) {
    return -EINVAL;
  }

  const unsigned long num_pages = length / PAGE_SIZE;
  const unsigned long area_struct_size =
      sizeof(vm_area_t) + (sizeof(bc_entry_t*) * num_pages);
  vm_area_t* area = (vm_area_t*)kmalloc(area_struct_size);
  if (!area) {
    return -ENOMEM;
  }
  kmemset(area, 0, area_struct_size);

  area->memobj = 0x0;
  area->vm_base = area->memobj_base = 0;
  area->vm_length = length;
  area->proc = 0x0;
  area->vm_proc_list = LIST_LINK_INIT;
  for (unsigned long i = 0; i < num_pages; ++i) {
    area->pages[i] = 0x0;
  }
  *area_out = area;
  return 0;
}
