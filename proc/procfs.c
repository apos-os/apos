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

#include <limits.h>

#include "common/alignment.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/list.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "memory/vm_area.h"
#include "proc/process.h"
#include "proc/spinlock.h"
#include "proc/user.h"
#include "vfs/cbfs.h"
#include "vfs/vfs.h"
#include "vfs/vnode.h"
#include "vfs/vfs_util.h"

// Constants that help us carve up the dynamic vnode space.  Each process gets a
// certain number of vnodes, which we partition for entries for the VM map, fds,
// etc.  That lets us dynamically determine what entry should be created just
// based on the vnode number.
#define PROC_VNODE_NUM_STATIC 10000
#define PROC_VNODE_OFFSET     PROC_VNODE_NUM_STATIC
#define PROC_VNODES_PER_PROC  1000
#define PROC_VNODE_DIR_OFFSET 0
#define PROC_VNODE_VM_OFFSET  1
#define PROC_VNODE_STATUS_OFFSET  2
#define PROC_VNODE_CWD_OFFSET  3

static inline int proc_dir_vnode(kpid_t pid) {
  return PROC_VNODE_OFFSET + pid * PROC_VNODES_PER_PROC + PROC_VNODE_DIR_OFFSET;
}

static inline kpid_t proc_vnode_to_pid(int vnode) {
  return (vnode - PROC_VNODE_OFFSET) / PROC_VNODES_PER_PROC;
}

static inline int proc_vnode_to_offset(int vnode) {
  return (vnode - PROC_VNODE_OFFSET) % PROC_VNODES_PER_PROC;
}

_Static_assert(PROC_VNODES_PER_PROC >= PROC_MAX_FDS, "Not enough vnode space");

static int vm_read(fs_t* fs, void* arg, int vnode, int offset, void* buf,
                   int buflen);
static int status_read(fs_t* fs, void* arg, int vnode, int offset, void* buf,
                       int buflen);
static int cwd_readlink(fs_t* fs, void* arg, int vnode, void* buf, int buflen);

// Helper struct for defining entries in the process directories.
typedef struct {
  // Name of the entry.
  const char* name;

  // Offset of this vnode in the process's vnode space.
  int vnode_offset;

  // Function to read the file.
  cbfs_read_t read_cb;

  // ...or the symlink, if a symlink.
  cbfs_readlink_t readlink_cb;
} proc_entry_spec_t;

const proc_entry_spec_t kStaticPerProcEntries[] = {
  {"vm", PROC_VNODE_VM_OFFSET, vm_read, 0x0},
  {"status", PROC_VNODE_STATUS_OFFSET, status_read, 0x0},
  {"cwd", PROC_VNODE_CWD_OFFSET, 0x0, &cwd_readlink},
};

const unsigned int kNumStaticEntries =
    sizeof(kStaticPerProcEntries) / sizeof(proc_entry_spec_t);

static int vm_read(fs_t* fs, void* arg, int vnode, int offset, void* buf,
                   int buflen) {
  // TODO(aoates): handle non-zero offsets
  if (offset > 0) return 0;

  const kpid_t pid = proc_vnode_to_pid(vnode);
  if (pid < 0 || pid >= PROC_MAX_PROCS) return -EINVAL;
  process_t* const proc = proc_get_ref(pid);
  if (!proc) return -EINVAL;

  char* tbuf = kmalloc(1024);

  pmutex_lock(&proc->mu);
  list_link_t* link = proc->vm_area_list.head;
  while (link && offset < buflen) {
    vm_area_t* area = container_of(link, vm_area_t, vm_proc_list);
    ksprintf(tbuf,
             "< start: 0x%" PRIxADDR "  end: 0x%" PRIxADDR "  memobj: %p >\n",
             area->vm_base, area->vm_base + area->vm_length, area->memobj);
    kstrncpy(buf + offset, tbuf, buflen - offset);
    offset += kstrlen(tbuf);
    link = link->next;
  }
  pmutex_unlock(&proc->mu);

  proc_put(proc);
  kfree(tbuf);
  return kstrlen(buf);
}

static int status_read(fs_t* fs, void* arg, int vnode, int offset, void* buf,
                       int buflen) {
  // TODO(aoates): handle non-zero offsets
  if (offset > 0) return 0;

  const kpid_t pid = proc_vnode_to_pid(vnode);
  if (pid < 0 || pid >= PROC_MAX_PROCS) return -EINVAL;
  process_t* const proc = proc_get_ref(pid);
  if (!proc) return -EINVAL;

  char* cwd = kmalloc(VFS_MAX_PATH_LENGTH);
  pmutex_lock(&proc->mu);
  if (proc->cwd) {
    int result = vfs_get_vnode_dir_path(proc->cwd, cwd, VFS_MAX_PATH_LENGTH);
    if (result < 0)
      ksprintf(cwd, "<unable to determine cwd: %s>", errorname(-result));
  } else {
    kstrcpy(cwd, "<none>");
  }

  char* tbuf = kmalloc(1024);
  kspin_lock(&g_proc_table_lock);
  int pgroup = proc->pgroup;
  kuid_t ruid = proc->ruid;
  kgid_t rgid = proc->rgid;
  kuid_t euid = proc->euid;
  kgid_t egid = proc->egid;
  kuid_t suid = proc->suid;
  kgid_t sgid = proc->sgid;
  kspin_unlock(&g_proc_table_lock);

  kspin_lock(&proc->spin_mu);
  ksprintf(tbuf,
           "pid: %d\n"
           "state: %s\n"
           "ppid: %d\n"
           "cwd: %s\n"
           "ruid/rgid: %5d %5d\n"
           "euid/egid: %5d %5d\n"
           "suid/sgid: %5d %5d\n"
           "pgroup: %d\n"
           "exec'ed: %d\n"
           "user_arch: %d\n"
           "children:\n"
           "",
           pid, proc_state_to_string(proc->state),
           proc->parent ? proc->parent->id : -1, cwd, ruid, rgid, euid, egid,
           suid, sgid, pgroup, proc->execed, proc->user_arch);
  char* buf_ptr = tbuf + kstrlen(tbuf);
  for (list_link_t* link = proc->children_list.head;
       link != 0x0;
       link = link->next) {
    process_t* const child = container_of(link, process_t, children_link);
    kspin_lock(&child->spin_mu);
    ksprintf(buf_ptr, "  %5d (%s)\n", child->id,
             proc_state_to_string(child->state));
    kspin_unlock(&child->spin_mu);
    buf_ptr += kstrlen(buf_ptr);
  }
  kspin_unlock(&proc->spin_mu);
  kstrncpy(buf, tbuf, buflen);
  ((char*)buf)[buflen - 1] = '\0';

  pmutex_unlock(&proc->mu);
  proc_put(proc);
  kfree(tbuf);
  kfree(cwd);
  return kstrlen(buf);
}

static int cwd_readlink(fs_t* fs, void* arg, int vnode, void* buf, int buflen) {
  const kpid_t pid = proc_vnode_to_pid(vnode);
  if (pid < 0 || pid >= PROC_MAX_PROCS) return -EINVAL;

  process_t* const proc = proc_get_ref(pid);
  if (!proc) return -EINVAL;

  char* cwd = kmalloc(VFS_MAX_PATH_LENGTH);
  pmutex_lock(&proc->mu);
  int result = vfs_get_vnode_dir_path(proc->cwd, cwd, VFS_MAX_PATH_LENGTH);
  if (result >= 0) kstrncpy(buf, cwd, result);
  pmutex_unlock(&proc->mu);

  proc_put(proc);
  kfree(cwd);
  return result;
}

static int vnode_cache_read(fs_t* fs, void* arg, int vnode, int offset,
                            void* buf, int buflen) {
  return vfs_print_vnode_cache(offset, buf, buflen);
}

// getdents callback for a particular proc's directory.
static int single_proc_getdents(fs_t* fs, int vnode_num, void* arg, int offset,
                                list_t* list_out, void* buf, int buflen);

static int procfs_get_vnode(fs_t* fs, void* arg, int vnode,
                            cbfs_inode_t* inode_out) {
  if (vnode < PROC_VNODE_OFFSET) {
    return -EINVAL;
  }

  const int proc = proc_vnode_to_pid(vnode);
  const int proc_offset = proc_vnode_to_offset(vnode);

  if (proc < 0 || proc >= PROC_MAX_PROCS) return -EINVAL;

  // Per-process directory.
  if (proc_offset == PROC_VNODE_DIR_OFFSET) {
    cbfs_inode_create_directory(inode_out, vnode, fs->get_root(fs),
                                &single_proc_getdents, 0x0, SUPERUSER_UID,
                                SUPERUSER_GID, VFS_S_IRUSR | VFS_S_IXUSR);
    return 0;
  }

  for (unsigned int i = 0; i < kNumStaticEntries; ++i) {
    const proc_entry_spec_t* entry_spec = &kStaticPerProcEntries[i];
    if (proc_offset == entry_spec->vnode_offset) {
      if (entry_spec->read_cb) {
        cbfs_inode_create_file(inode_out, vnode, entry_spec->read_cb, 0x0,
                               SUPERUSER_UID, SUPERUSER_GID, VFS_S_IRUSR);
        return 0;
      } else if (entry_spec->readlink_cb) {
        cbfs_inode_create_symlink(inode_out, vnode, entry_spec->readlink_cb,
                                  0x0, SUPERUSER_UID, SUPERUSER_GID);
        return 0;
      } else {
        die("invalid entry in static procfs array");
      }
    }
  }

  return -ENOENT;
}

static int proc_getdents(fs_t* fs, int vnode_num, void* arg, int offset,
                         list_t* list_out, void* buf, int buflen) {
  ASSERT_ALIGNED(buf, cbfs_entry_t);
  int process_idx = -1;
  for (kpid_t pid = 0; pid < PROC_MAX_PROCS; ++pid) {
    process_t* proc = proc_get_ref(pid);
    if (!proc) continue;
    process_idx++;

    if (process_idx < offset) {
      proc_put(proc);
      continue;
    }

    char name[30];
    ksprintf(name, "%d", pid);
    const int entry_size = cbfs_entry_size(name);
    if (entry_size > buflen) {
      proc_put(proc);
      break;
    }

    cbfs_entry_t* entry = (cbfs_entry_t*)buf;
    cbfs_create_entry(entry, name, proc_dir_vnode(pid));
    list_push(list_out, &entry->link);

    buf += entry_size;
    buflen -= entry_size;
    proc_put(proc);
  }
  return 0;
}

static int single_proc_getdents(fs_t* fs, int vnode_num, void* arg, int offset,
                                list_t* list_out, void* buf, int buflen) {
  const kpid_t pid = proc_vnode_to_pid(vnode_num);
  for (unsigned int i = offset; i < kNumStaticEntries; ++i) {
    const proc_entry_spec_t* entry_spec = &kStaticPerProcEntries[i];
    const int entry_size = cbfs_entry_size(entry_spec->name);
    if (entry_size > buflen) return 0;

    const int entry_vnode = PROC_VNODE_OFFSET + pid * PROC_VNODES_PER_PROC +
                            entry_spec->vnode_offset;
    cbfs_entry_t* entry = (cbfs_entry_t*)buf;
    cbfs_create_entry(entry, kStaticPerProcEntries[i].name, entry_vnode);
    list_push(list_out, &entry->link);

    buf += entry_size;
    buflen -= entry_size;
  }

  return 0;
}

static int self_proc_symlink_readlink(fs_t* fs, void* arg, int vnode_num,
                                      void* buf, int buflen) {
  char pid[100];
  ksprintf(pid, "%d", proc_current()->id);
  const int len = min(buflen, kstrlen(pid));
  kstrncpy(buf, pid, len);
  return len;
}

fs_t* procfs_create(void) {
  fs_t* fs =
      cbfs_create("procfs", procfs_get_vnode, NULL, 0x0, PROC_VNODE_NUM_STATIC);

  int result = cbfs_directory_set_getdents(fs, "/", &proc_getdents, 0x0);
  if (result) {
    klogfm(KL_PROC, ERROR, "cannot set getdents for root of procfs: %s\n",
           errorname(-result));
  }

  cbfs_create_file(fs, "vnode", &vnode_cache_read, 0x0, VFS_S_IRWXU);
  cbfs_create_symlink(fs, "self", &self_proc_symlink_readlink, 0x0);

  return fs;
}

int procfs_create_path(const char* source, unsigned long flags,
                       const void* data, size_t data_len, fs_t** fs_out) {
  if (kstrcmp(source, "") != 0) {
    return -EINVAL;
  }

  *fs_out = procfs_create();
  return 0;
}
