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

#include "proc/procfs.h"

#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/list.h"
#include "memory/vm_area.h"
#include "proc/process.h"
#include "vfs/cbfs.h"
#include "vfs/vfs.h"
#include "vfs/vfs_util.h"

static int vm_read(fs_t* fs, void* arg, int offset, void* buf, int buflen) {
  // TODO(aoates): handle non-zero offsets
  if (offset > 0) return 0;

  char tbuf[1024];

  list_link_t* link = proc_current()->vm_area_list.head;
  while (link && offset < buflen) {
    vm_area_t* area = container_of(link, vm_area_t, vm_proc_list);
    ksprintf(tbuf, "< start: 0x%x  end: 0x%x  memobj: 0x%x >\n", area->vm_base,
             area->vm_base + area->vm_length, area->memobj);
    kstrncpy(buf + offset, tbuf, buflen - offset);
    offset += kstrlen(tbuf);
    link = link->next;
  }

  return kstrlen(buf);
}

static int vnode_cache_read(fs_t* fs, void* arg, int offset, void* buf,
                            int buflen) {
  return vfs_print_vnode_cache(offset, buf, buflen);
}

fs_t* procfs_create(void) {
  fs_t* fs = cbfs_create(0x0, 0x0);

  cbfs_create_file(fs, "self/vm", &vm_read, 0x0, VFS_S_IRWXU);
  cbfs_create_file(fs, "vnode", &vnode_cache_read, 0x0, VFS_S_IRWXU);

  return fs;
}

