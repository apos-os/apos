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
  char name[VFS_MAX_FILENAME_LENGTH];
  vnode_type_t type;

  // If type == VNODE_REGULAR.
  cbfs_read_t read_cb;
  void* arg;

  // If type == VNODE_DIRECTORY.
  list_t entries;

  uid_t uid;
  gid_t gid;
  mode_t mode;

  list_link_t link;
} cbfs_entry_t;

typedef struct {
  fs_t fs;
  int next_ino;
  cbfs_entry_t root;
  htbl_t vnode_table;
} cbfs_t;

static inline cbfs_t* fs_to_cbfs(fs_t* f) {
  return (cbfs_t*)f;
}

static cbfs_entry_t* lookup(cbfs_entry_t* parent, int num) {
  list_link_t* n = parent->entries.head;
  while (n) {
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);
    if (entry->num == num) return entry;
    n = n->next;
  }

  return 0x0;
}

static cbfs_entry_t* lookup_by_name(cbfs_entry_t* parent, const char* name) {
  list_link_t* n = parent->entries.head;
  while (n) {
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);
    if (kstrcmp(name, entry->name) == 0) return entry;
    n = n->next;
  }
  return 0x0;
}

// Insert a child into the parent's entry list, and update the vnode table.
static void insert_entry(cbfs_t* cfs, cbfs_entry_t* parent,
                         cbfs_entry_t* child) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  list_push(&parent->entries, &child->link);
}

// Create a new cbfs_entry_t with the given number.
cbfs_entry_t* create_entry(cbfs_t* cfs, int num) {
  cbfs_entry_t* entry = (cbfs_entry_t*)kmalloc(sizeof(cbfs_entry_t));
  entry->type = VNODE_INVALID;
  entry->num = num;
  entry->read_cb = 0x0;
  entry->arg = 0x0;
  entry->link = LIST_LINK_INIT;
  entry->entries = LIST_INIT;
  entry->mode = cfs->root.mode;
  entry->uid = cfs->root.uid;
  entry->gid = cfs->root.gid;

  return entry;
}

// Insert the given entry into the vnode table.
void add_entry_to_vnode_table(cbfs_t* cfs, cbfs_entry_t* entry) {
  void* unused_val;
  KASSERT(htbl_get(&cfs->vnode_table, entry->num, &unused_val) != 0);
  htbl_put(&cfs->vnode_table, entry->num, entry);
}

// Get the given entry from the vnode table.
cbfs_entry_t* get_entry(cbfs_t* cfs, int num) {
  void* ptr;
  if (htbl_get(&cfs->vnode_table, num, &ptr)) return 0x0;
  return (cbfs_entry_t*)ptr;
}

// Add standard directory entries ('.' and '..') to the given node.
void create_directory_entries(cbfs_t* cfs, cbfs_entry_t* parent,
                              cbfs_entry_t* dir) {
  const char* const kNames[] = {".", ".."};
  const int inos[] = {dir->num, parent->num};
  for (int i = 0; i < 2; ++i) {
    cbfs_entry_t* entry = create_entry(cfs, inos[i]);
    kstrcpy(entry->name, kNames[i]);
    entry->type = VNODE_DIRECTORY;

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
  add_entry_to_vnode_table(f, &f->root);
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
  cbfs_entry_t* parent = &cfs->root;
  while (*name_end != '\0') {
    if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

    char name[VFS_MAX_FILENAME_LENGTH];
    kstrncpy(name, name_start, name_end - name_start);
    name[name_end - name_start] = '\0';
    cbfs_entry_t* child = lookup_by_name(parent, name);

    if (!child) {
      // Create the directory.
      cbfs_entry_t* dir = create_entry(cfs, cfs->next_ino++);
      kstrcpy(dir->name, name);
      dir->type = VNODE_DIRECTORY;
      add_entry_to_vnode_table(cfs, dir);
      insert_entry(cfs, parent, dir);
      create_directory_entries(cfs, parent, dir);
      child = dir;
    }

    name_start = name_end + 1;
    name_end = kstrchrnul(name_start, '/');
    parent = child;
  }

  if (lookup_by_name(parent, name_start) != 0x0) return -EEXIST;
  if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

  cbfs_entry_t* entry = create_entry(cfs, cfs->next_ino++);
  kstrcpy(entry->name, name_start);
  entry->type = VNODE_REGULAR;
  entry->read_cb = read_cb;
  entry->arg = arg;
  entry->mode = mode;
  entry->uid = proc_current()->euid;
  entry->gid = proc_current()->egid;

  add_entry_to_vnode_table(cfs, entry);
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
  cbfs_entry_t* entry = get_entry(cfs, vnode->num);
  if (!entry) return -ENOENT;

  vnode->type = entry->type;
  vnode->uid = entry->uid;
  vnode->gid = entry->gid;
  vnode->mode = entry->mode;
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

  cbfs_entry_t* entry = get_entry(cfs, vnode->num);
  if (!entry) return -ENOENT;

  entry->uid = vnode->uid;
  entry->gid = vnode->gid;
  entry->mode = vnode->mode;

  return 0;
}

static int cbfs_lookup(vnode_t* parent, const char* name) {
  cbfs_t* cfs = fs_to_cbfs(parent->fs);
  cbfs_entry_t* parent_entry = get_entry(cfs, parent->num);

  cbfs_entry_t* entry = lookup_by_name(parent_entry, name);
  if (entry) return entry->num;
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
  cbfs_entry_t* entry = get_entry(cfs, vnode->num);
  if (entry->type == VNODE_DIRECTORY) return -EISDIR;

  return entry->read_cb(vnode->fs, entry->arg, offset, buf, bufsize);
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
  cbfs_entry_t* entry = get_entry(cfs, vnode->num);

  list_link_t* n = entry->entries.head;
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
  cbfs_entry_t* entry = get_entry(cfs, vnode->num);

  stat_out->st_mode =
      (entry->type == VNODE_DIRECTORY) ? VFS_S_IFDIR : VFS_S_IFREG |
      entry->mode;
  stat_out->st_nlink = (entry->type == VNODE_DIRECTORY) ? 2 : 1;
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
