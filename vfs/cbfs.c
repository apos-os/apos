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

#include "vfs/cbfs.h"

#include "common/errno.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "proc/user.h"
#include "vfs/vfs.h"

#define CBFS_ROOT_INO 0
#define VNODE_TABLE_BUCKETS 100

typedef struct {
  int num;
  vnode_type_t type;

  // If type == VNODE_REGULAR.
  cbfs_read_t read_cb;
  void* arg;

  // If type == VNODE_DIRECTORY.
  list_t entries;

  uid_t uid;
  gid_t gid;
  mode_t mode;
} cbfs_inode_t;

typedef struct {
  int num;
  list_link_t link;
  char name[];
} cbfs_entry_t;

typedef struct {
  fs_t fs;
  int next_ino;
  cbfs_inode_t root;
  htbl_t vnode_table;
} cbfs_t;

static inline cbfs_t* fs_to_cbfs(fs_t* f) {
  return (cbfs_t*)f;
}

// Get the given inode from the vnode table.  Returns 0 on success, and sets
// *ptr_out to the inode.
static int get_inode(cbfs_t* cfs, int num, cbfs_inode_t** ptr_out) {
  void* ptr;
  if (htbl_get(&cfs->vnode_table, num, &ptr)) return -ENOENT;
  *ptr_out = (cbfs_inode_t*)ptr;
  return 0;
}

static cbfs_inode_t* lookup_by_name(cbfs_t* fs, cbfs_inode_t* parent,
                                    const char* name) {
  list_link_t* n = parent->entries.head;
  while (n) {
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);
    if (kstrcmp(name, entry->name) == 0) {
      cbfs_inode_t* inode = 0x0;
      int result = get_inode(fs, entry->num, &inode);
      if (result) return 0x0;
      else return inode;
    }
    n = n->next;
  }
  return 0x0;
}

// Insert a child into the parent's entry list.
static void insert_entry(cbfs_t* cfs, cbfs_inode_t* parent,
                         cbfs_entry_t* child) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  list_push(&parent->entries, &child->link);
}

// Create a new cbfs_inode_t with the given number.
cbfs_inode_t* create_inode(cbfs_t* cfs, int num) {
  cbfs_inode_t* inode = (cbfs_inode_t*)kmalloc(sizeof(cbfs_inode_t));
  inode->type = VNODE_INVALID;
  inode->num = num;
  inode->read_cb = 0x0;
  inode->arg = 0x0;
  inode->entries = LIST_INIT;
  inode->mode = cfs->root.mode;
  inode->uid = cfs->root.uid;
  inode->gid = cfs->root.gid;

  return inode;
}

// Create a new cbfs_entry_t with the given name and number.
cbfs_entry_t* create_entry(cbfs_t* cfs, int num, const char name[]) {
  cbfs_entry_t* entry =
      (cbfs_entry_t*)kmalloc(sizeof(cbfs_entry_t) + kstrlen(name) + 1);
  kstrcpy(entry->name, name);
  entry->num = num;
  entry->link = LIST_LINK_INIT;

  return entry;
}

// Insert the given inode into the vnode table.
void add_inode_to_vnode_table(cbfs_t* cfs, cbfs_inode_t* inode) {
  void* unused_val;
  KASSERT(htbl_get(&cfs->vnode_table, inode->num, &unused_val) != 0);
  htbl_put(&cfs->vnode_table, inode->num, inode);
}

// Add standard directory entries ('.' and '..') to the given node.
void create_directory_entries(cbfs_t* cfs, cbfs_inode_t* parent,
                              cbfs_inode_t* dir) {
  const char* const kNames[] = {".", ".."};
  const int inos[] = {dir->num, parent->num};
  for (int i = 0; i < 2; ++i) {
    cbfs_entry_t* entry = create_entry(cfs, inos[i], kNames[i]);

    insert_entry(cfs, dir, entry);
  }
}

static vnode_t* cbfs_alloc_vnode(struct fs* fs);
static int cbfs_get_root(struct fs* fs);
static int cbfs_get_vnode(vnode_t* vnode);
static int cbfs_put_vnode(vnode_t* vnode);
static int cbfs_lookup(vnode_t* parent, const char* name);
static int cbfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev);
static int cbfs_mkdir(vnode_t* parent, const char* name);
static int cbfs_rmdir(vnode_t* parent, const char* name);
static int cbfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int cbfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize);
static int cbfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int cbfs_unlink(vnode_t* parent, const char* name);
static int cbfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
static int cbfs_stat(vnode_t* vnode, apos_stat_t* stat_out);
static int cbfs_read_page(vnode_t* vnode, int page_offset, void* buf);
static int cbfs_write_page(vnode_t* vnode, int page_offset, const void* buf);

fs_t* cbfs_create(void) {
  cbfs_t* f = (cbfs_t*)kmalloc(sizeof(cbfs_t));
  vfs_fs_init(&f->fs);

  kstrcpy(f->fs.fstype, "cbfs");
  f->fs.alloc_vnode = &cbfs_alloc_vnode;
  f->fs.get_root = &cbfs_get_root;
  f->fs.get_vnode = &cbfs_get_vnode;
  f->fs.put_vnode = &cbfs_put_vnode;
  f->fs.lookup = &cbfs_lookup;
  f->fs.mknod = &cbfs_mknod;
  f->fs.mkdir = &cbfs_mkdir;
  f->fs.rmdir = &cbfs_rmdir;
  f->fs.read = &cbfs_read;
  f->fs.write = &cbfs_write;
  f->fs.link = &cbfs_link;
  f->fs.unlink = &cbfs_unlink;
  f->fs.getdents = &cbfs_getdents;
  f->fs.stat = &cbfs_stat;
  f->fs.read_page = &cbfs_read_page;
  f->fs.write_page = &cbfs_write_page;

  f->next_ino = 1;
  f->root.num = CBFS_ROOT_INO;
  f->root.type = VNODE_DIRECTORY;
  f->root.entries = LIST_INIT;
  f->root.uid = SUPERUSER_UID;
  f->root.gid = SUPERUSER_GID;
  f->root.mode = VFS_S_IRUSR | VFS_S_IXUSR | VFS_S_IRGRP | VFS_S_IXGRP |
      VFS_S_IROTH | VFS_S_IXOTH;

  htbl_init(&f->vnode_table, VNODE_TABLE_BUCKETS);
  add_inode_to_vnode_table(f, &f->root);
  create_directory_entries(f, &f->root, &f->root);

  return &f->fs;
}

void cbfs_free(fs_t* fs) {
  cbfs_t* cfs = fs_to_cbfs(fs);
  // TODO(aoates): clean up all entries
  htbl_cleanup(&cfs->vnode_table);
  kfree(cfs);
}

int cbfs_create_file(fs_t* fs, const char* name,
                     cbfs_read_t read_cb, void* arg, mode_t mode) {
  cbfs_t* cfs = fs_to_cbfs(fs);

  const char* name_start = name;
  const char* name_end = kstrchrnul(name_start, '/');
  cbfs_inode_t* parent = &cfs->root;
  while (*name_end != '\0') {
    if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

    char name[VFS_MAX_FILENAME_LENGTH];
    kstrncpy(name, name_start, name_end - name_start);
    name[name_end - name_start] = '\0';
    cbfs_inode_t* child = lookup_by_name(cfs, parent, name);

    if (!child) {
      // Create the directory.
      cbfs_inode_t* dir = create_inode(cfs, cfs->next_ino++);
      dir->type = VNODE_DIRECTORY;
      add_inode_to_vnode_table(cfs, dir);
      create_directory_entries(cfs, parent, dir);

      cbfs_entry_t* entry = create_entry(cfs, dir->num, name);
      insert_entry(cfs, parent, entry);
      child = dir;
    }

    name_start = name_end + 1;
    name_end = kstrchrnul(name_start, '/');
    parent = child;
  }

  if (lookup_by_name(cfs, parent, name_start) != 0x0) return -EEXIST;
  if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

  cbfs_inode_t* inode = create_inode(cfs, cfs->next_ino++);
  inode->type = VNODE_REGULAR;
  inode->read_cb = read_cb;
  inode->arg = arg;
  inode->mode = mode;
  inode->uid = proc_current()->euid;
  inode->gid = proc_current()->egid;
  add_inode_to_vnode_table(cfs, inode);

  cbfs_entry_t* entry = create_entry(cfs, inode->num, name_start);
  insert_entry(cfs, parent, entry);

  return 0;
}

static vnode_t* cbfs_alloc_vnode(struct fs* fs) {
  return (vnode_t*)kmalloc(sizeof(vnode_t));
}

static int cbfs_get_root(struct fs* fs) {
  return CBFS_ROOT_INO;
}

static int cbfs_get_vnode(vnode_t* vnode) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &inode);
  if (result) return result;

  vnode->type = inode->type;
  vnode->uid = inode->uid;
  vnode->gid = inode->gid;
  vnode->mode = inode->mode;
  kstrcpy(vnode->fstype, "cbfs");
  return 0;
}

static int cbfs_put_vnode(vnode_t* vnode) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  if (vnode->num == CBFS_ROOT_INO) {
    cfs->root.uid = vnode->uid;
    cfs->root.gid = vnode->gid;
    cfs->root.mode = vnode->mode;
    return 0;
  }

  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &inode);
  if (result) return result;

  inode->uid = vnode->uid;
  inode->gid = vnode->gid;
  inode->mode = vnode->mode;

  return 0;
}

static int cbfs_lookup(vnode_t* parent, const char* name) {
  cbfs_t* cfs = fs_to_cbfs(parent->fs);

  cbfs_inode_t* parent_inode = 0x0;
  int result = get_inode(cfs, parent->num, &parent_inode);
  if (result) {
    klogfm(KL_VFS, WARNING,
           "cbfs: unable to get parent inode in cbfs_lookup(): %s\n", result);
    return result;
  }

  cbfs_inode_t* inode = lookup_by_name(cfs, parent_inode, name);
  if (inode) return inode->num;
  else return -ENOENT;
}

static int cbfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev) {
  return -EACCES;
}

static int cbfs_mkdir(vnode_t* parent, const char* name) {
  return -EACCES;
}

static int cbfs_rmdir(vnode_t* parent, const char* name) {
  return -EACCES;
}

static int cbfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &inode);
  if (result) return result;
  if (inode->type == VNODE_DIRECTORY) return -EISDIR;

  return inode->read_cb(vnode->fs, inode->arg, offset, buf, bufsize);
}

static int cbfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize) {
  return -EACCES;
}

static int cbfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  return -EACCES;
}

static int cbfs_unlink(vnode_t* parent, const char* name) {
  return -EACCES;
}

static int cbfs_getdents(vnode_t* vnode, int offset, void* outbuf,
                         int outbufsize) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &inode);
  if (result) return result;

  list_link_t* n = inode->entries.head;
  int idx = 0;
  while (n && idx < offset) {
    n = n->next;
    idx++;
  }

  if (!n) return 0;

  int bytes_written = 0;
  while (1) {
    if (!n) break;
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);

    const int dirent_len = sizeof(dirent_t) + kstrlen(entry->name) + 1;
    if (bytes_written + dirent_len > outbufsize) break;

    dirent_t* d = (dirent_t*)(((const char*)outbuf) + bytes_written);
    d->vnode = entry->num;
    d->offset = idx + 1;
    d->length = dirent_len;
    kstrcpy(d->name, entry->name);

    bytes_written += dirent_len;
    n = n->next;
    idx++;
  }
  return bytes_written;
}

static int cbfs_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &inode);
  if (result) return result;

  stat_out->st_mode =
      (inode->type == VNODE_DIRECTORY) ? VFS_S_IFDIR : VFS_S_IFREG |
      inode->mode;
  stat_out->st_nlink = (inode->type == VNODE_DIRECTORY) ? 2 : 1;
  stat_out->st_rdev = mkdev(0, 0);
  stat_out->st_size = 2 * sizeof(dirent_t) + 5;
  stat_out->st_blksize = 512;
  stat_out->st_blocks = 1;
  return 0;
}

static int cbfs_read_page(vnode_t* vnode, int page_offset, void* buf) {
  return -ENOTSUP;
}

static int cbfs_write_page(vnode_t* vnode, int page_offset, const void* buf) {
  return -ENOTSUP;
}
