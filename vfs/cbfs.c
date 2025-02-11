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

#include <stdalign.h>

#include "common/errno.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "memory/kmalloc.h"
#include "proc/user.h"
#include "vfs/vfs.h"

#define CBFS_ROOT_INO 0
#define VNODE_TABLE_BUCKETS 100

struct cbfs_inode {
  int num;
  vnode_type_t type;

  // If type == VNODE_REGULAR.
  cbfs_read_t read_cb;

  // If type == VNODE_DIRECTORY.
  list_t entries;
  cbfs_getdents_t getdents_cb;
  char static_entries[sizeof(cbfs_entry_t) * 2 + 16];

  // If type == VNODE_SYMLINK.
  cbfs_readlink_t readlink_cb;

  void* arg;

  kuid_t uid;
  kgid_t gid;
  kmode_t mode;
};

const cbfs_inode_t INIT_INODE = {
    -1, VNODE_INVALID, 0x0, LIST_INIT_STATIC, 0x0, {}, 0x0, 0x0, -1, -1, 0,
};

typedef struct {
  fs_t fs;
  int next_ino;
  int max_static_vnode;
  cbfs_inode_t root;
  htbl_t vnode_table;
  cbfs_lookup_t lookup_cb;
  cbfs_destroy_t destroy_cb;
  void* cb_arg;
} cbfs_t;

static inline cbfs_t* fs_to_cbfs(fs_t* f) {
  return (cbfs_t*)f;
}

static inline int alloc_inode_num(cbfs_t* fs) {
  if (fs->next_ino >= fs->max_static_vnode)
    return -ENOSPC;
  else
    return fs->next_ino++;
}

// Get the given inode from the vnode table.  Returns 0 on success, and sets
// *ptr_out to the inode.  If the vnode isn't in the table, but the cbfs has a
// lookup callback, it is run, and the generated vnode (if any) is placed in
// tmp, and *ptr_out is set to tmp.  Thus, tmp should point to a cbfs_inode_t
// whose lifetime exceeds the use of ptr_out (e.g. a cbfs_inode_t allocated on
// the callers stack).
static int get_inode(cbfs_t* cfs, int num, cbfs_inode_t* tmp,
                     cbfs_inode_t** ptr_out) {
  void* ptr;
  if (htbl_get(&cfs->vnode_table, num, &ptr) == 0) {
    *ptr_out = (cbfs_inode_t*)ptr;
    return 0;
  } else if (cfs->lookup_cb) {
    int result = cfs->lookup_cb(&cfs->fs, cfs->cb_arg, num, tmp);
    *ptr_out = tmp;
    return result;
  }

  return -ENOENT;
}

// Looks for the given entry in the list, returning 0 if succesful, or -error if
// not.  The number of entries scanned (equal to the size of the list) is stored
// in |scanned_out|.
static int lookup_in_entry_list(cbfs_t* fs, const list_t* list,
                                const char* name, cbfs_inode_t* generated_inode,
                                cbfs_inode_t** ptr_out, int* scanned_out) {
  list_link_t* n = list->head;
  *scanned_out = 0;
  while (n) {
    (*scanned_out)++;
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);
    if (kstrcmp(name, entry->name) == 0) {
      return get_inode(fs, entry->num, generated_inode, ptr_out);
    }
    n = n->next;
  }
  return -ENOENT;
}

// As above.  *ptr_out is set too either an existing inode in the vnode table,
// or to generated_inode (which is filled with the appropriate data).
static int lookup_by_name(cbfs_t* fs, cbfs_inode_t* parent, const char* name,
                          cbfs_inode_t* generated_inode,
                          cbfs_inode_t** ptr_out) {
  if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

  int scanned;
  int result = lookup_in_entry_list(fs, &parent->entries, name, generated_inode,
                                    ptr_out, &scanned);
  if (result >= 0)
    return 0;
  else if (result != -ENOENT)
    return result;

  if (parent->getdents_cb) {
    list_t list = LIST_INIT;
    int offset = 0;
    do {
      list = LIST_INIT;
      const int kCbfsEntryBufSize = 1000;
      char cbfs_entry_buf[kCbfsEntryBufSize];
      result = parent->getdents_cb(&fs->fs, parent->num, parent->arg, offset,
                                   &list, cbfs_entry_buf, kCbfsEntryBufSize);
      if (result < 0) return result;

      result = lookup_in_entry_list(fs, &list, name, generated_inode, ptr_out,
                                    &scanned);
      if (result >= 0)
        return 0;
      else if (result != -ENOENT)
        return result;

      offset += scanned;
    } while (!list_empty(&list));
  }
  return -ENOENT;
}

// Insert a child into the parent's entry list.
static void insert_entry(cbfs_inode_t* parent, cbfs_entry_t* child) {
  KASSERT(parent->type == VNODE_DIRECTORY);
  list_push(&parent->entries, &child->link);
}

static void init_inode(cbfs_inode_t* inode) {
  *inode = INIT_INODE;
}

// Create a new cbfs_inode_t with the given number.
static cbfs_inode_t* create_inode(cbfs_t* cfs, int num) {
  cbfs_inode_t* inode = (cbfs_inode_t*)kmalloc(sizeof(cbfs_inode_t));
  init_inode(inode);
  inode->num = num;
  inode->mode = cfs->root.mode;
  inode->uid = cfs->root.uid;
  inode->gid = cfs->root.gid;

  return inode;
}

// Clean up the given inode (in particular, deleting directory entries).
static void cleanup_inode(cbfs_inode_t* inode) {
  if (inode->type == VNODE_DIRECTORY) {
    list_link_t* l = list_pop(&inode->entries);  // "."
    KASSERT_DBG(kstrcmp(container_of(l, cbfs_entry_t, link)->name, ".") == 0);
    l = list_pop(&inode->entries);  // ".."
    KASSERT_DBG(kstrcmp(container_of(l, cbfs_entry_t, link)->name, "..") == 0);
  }

  while (!list_empty(&inode->entries)) {
    list_link_t* link = list_pop(&inode->entries);
    cbfs_entry_t* entry = container_of(link, cbfs_entry_t, link);
    kfree(entry);
  }
}

// Create a new cbfs_entry_t with the given name and number.
static cbfs_entry_t* create_entry(int num, const char name[], char* buf) {
  cbfs_entry_t* entry =
      (cbfs_entry_t*)(buf ? buf
                          : kmalloc(sizeof(cbfs_entry_t) + kstrlen(name) + 1));
  kstrcpy(entry->name, name);
  entry->num = num;
  entry->link = LIST_LINK_INIT;

  return entry;
}

// Insert the given inode into the vnode table.
static void add_inode_to_vnode_table(cbfs_t* cfs, cbfs_inode_t* inode) {
  void* unused_val;
  KASSERT(htbl_get(&cfs->vnode_table, inode->num, &unused_val) != 0);
  htbl_put(&cfs->vnode_table, inode->num, inode);
}

// Add standard directory entries ('.' and '..') to the given node.
static void create_directory_entries(int parent_num, cbfs_inode_t* dir) {
  const char* const kNames[] = {".", ".."};
  const int inos[] = {dir->num, parent_num};
  size_t offset = 0;
  for (int i = 0; i < 2; ++i) {
    offset = align_up(offset, sizeof(addr_t));
    KASSERT_DBG(offset + cbfs_entry_size(kNames[i]) <=
                sizeof(dir->static_entries));
    cbfs_entry_t* entry =
        create_entry(inos[i], kNames[i], &dir->static_entries[offset]);

    insert_entry(dir, entry);
    offset += cbfs_entry_size(kNames[i]);
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
static int cbfs_rmdir(vnode_t* parent, const char* name, const vnode_t* child);
static int cbfs_read(vnode_t* vnode, int offset, void* buf, int bufsize);
static int cbfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize);
static int cbfs_link(vnode_t* parent, vnode_t* vnode, const char* name);
static int cbfs_unlink(vnode_t* parent, const char* name, const vnode_t* child);
static int cbfs_getdents(vnode_t* vnode, int offset, void* buf, int bufsize);
static int cbfs_stat(vnode_t* vnode, apos_stat_t* stat_out);
static int cbfs_symlink(vnode_t* parent, const char* name, const char* path);
static int cbfs_readlink(vnode_t* node, char* buf, int bufsize);
static int cbfs_truncate(vnode_t* node, koff_t length);
static int cbfs_read_page(vnode_t* vnode, int page_offset, void* buf);
static int cbfs_write_page(vnode_t* vnode, int page_offset, const void* buf);

fs_t* cbfs_create(const char* type, cbfs_lookup_t lookup_cb,
                  cbfs_destroy_t destroy_cb, void* cb_arg,
                  int max_static_vnode) {
  cbfs_t* f = (cbfs_t*)kmalloc(sizeof(cbfs_t));
  vfs_fs_init(&f->fs);

  kstrcpy(f->fs.fstype, type);
  f->fs.destroy_fs = &cbfs_free;
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
  f->fs.symlink = &cbfs_symlink;
  f->fs.readlink = &cbfs_readlink;
  f->fs.truncate = &cbfs_truncate;
  f->fs.read_page = &cbfs_read_page;
  f->fs.write_page = &cbfs_write_page;

  f->next_ino = 1;
  f->max_static_vnode = max_static_vnode;
  init_inode(&f->root);
  f->root.num = CBFS_ROOT_INO;
  f->root.type = VNODE_DIRECTORY;
  f->root.entries = LIST_INIT;
  f->root.uid = SUPERUSER_UID;
  f->root.gid = SUPERUSER_GID;
  f->root.mode = VFS_S_IRUSR | VFS_S_IXUSR | VFS_S_IRGRP | VFS_S_IXGRP |
      VFS_S_IROTH | VFS_S_IXOTH;

  htbl_init(&f->vnode_table, VNODE_TABLE_BUCKETS);
  add_inode_to_vnode_table(f, &f->root);
  create_directory_entries(f->root.num, &f->root);

  f->lookup_cb = lookup_cb;
  f->destroy_cb = destroy_cb;
  f->cb_arg = cb_arg;

  return &f->fs;
}

static void inode_cleanup_func(void* arg, htbl_key_t key, void* value) {
  cbfs_t* cfs = (cbfs_t*)arg;
  cbfs_inode_t* inode = (cbfs_inode_t*)value;
  cleanup_inode(inode);
  if (value != &cfs->root)
    kfree(value);
}

void cbfs_free(fs_t* fs) {
  cbfs_t* cfs = fs_to_cbfs(fs);
  if (cfs->destroy_cb) {
    cfs->destroy_cb(fs, cfs->cb_arg);
  }
  htbl_iterate(&cfs->vnode_table, &inode_cleanup_func, cfs);
  htbl_cleanup(&cfs->vnode_table);
  kfree(cfs);
}

void cbfs_inode_create_file(cbfs_inode_t* inode, int num, cbfs_read_t read_cb,
                            void* read_arg, kuid_t uid, kgid_t gid, kmode_t mode) {
  init_inode(inode);
  inode->type = VNODE_REGULAR;
  inode->num = num;
  inode->read_cb = read_cb;
  inode->arg = read_arg;
  inode->uid = uid;
  inode->gid = gid;
  inode->mode = mode;
}

void cbfs_inode_create_directory(cbfs_inode_t* inode, int num, int parent_num,
                                 cbfs_getdents_t getdents_cb,
                                 void* getdents_arg, kuid_t uid, kgid_t gid,
                                 kmode_t mode) {
  init_inode(inode);
  inode->type = VNODE_DIRECTORY;
  inode->num = num;
  inode->getdents_cb = getdents_cb;
  inode->arg = getdents_arg;
  inode->uid = uid;
  inode->gid = gid;
  inode->mode = mode;

  create_directory_entries(parent_num, inode);
}

void cbfs_inode_create_symlink(cbfs_inode_t* inode, int num,
                               cbfs_readlink_t readlink_cb, void* readlink_arg,
                               kuid_t uid, kgid_t gid) {
  init_inode(inode);
  inode->type = VNODE_SYMLINK;
  inode->num = num;
  inode->readlink_cb = readlink_cb;
  inode->arg = readlink_arg;
  inode->uid = uid;
  inode->gid = gid;
  inode->mode = VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO;
}

void cbfs_create_entry(cbfs_entry_t* entry, const char* name, int num) {
  entry->num = num;
  entry->link = LIST_LINK_INIT;
  kstrcpy(entry->name, name);
}

static inline const char* skip_slashes(const char* s) {
  while (*s && *s == '/') s++;
  return s;
}

// Lookup the given path and return the inode of the parent (if possible) and
// the base name of the file, or an error.  If create_directories is non-zero,
// any missing parent directories will be created.
static int lookup_path(cbfs_t* cfs, const char* name, int create_directories,
                       char* base_name_out, cbfs_inode_t** parent_out) {
  const char* name_start = skip_slashes(name);

  const char* name_end = kstrchrnul(name_start, '/');
  const char* next_start = skip_slashes(name_end);
  cbfs_inode_t* parent = &cfs->root;
  while (*next_start != '\0') {
    if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

    char name[VFS_MAX_FILENAME_LENGTH];
    kstrncpy(name, name_start, name_end - name_start);
    name[name_end - name_start] = '\0';
    cbfs_inode_t generated_child = INIT_INODE;
    cbfs_inode_t* child = 0x0;
    int result = lookup_by_name(cfs, parent, name, &generated_child, &child);
    if (result != 0 && result != -ENOENT) return result;
    // Don't descend into dynamically-created directories.
    if (child == &generated_child) return -ENOENT;
    if (result == -ENOENT) {
      if (!create_directories) return -ENOENT;

      // Create the directory.
      const int dir_inode = alloc_inode_num(cfs);
      if (dir_inode < 0) return dir_inode;

      cbfs_inode_t* dir = create_inode(cfs, dir_inode);
      dir->type = VNODE_DIRECTORY;
      add_inode_to_vnode_table(cfs, dir);
      create_directory_entries(parent->num, dir);

      cbfs_entry_t* entry = create_entry(dir->num, name, NULL);
      insert_entry(parent, entry);
      child = dir;
    }

    name_start = next_start;
    name_end = kstrchrnul(name_start, '/');
    next_start = skip_slashes(name_end);
    parent = child;
  }

  kstrncpy(base_name_out, name_start, name_end - name_start);
  base_name_out[name_end - name_start] = '\0';
  *parent_out = parent;

  return 0;
}

static int create_path(cbfs_t* cfs, const char* name,
                       char* base_name_out, cbfs_inode_t** parent_out) {
  return lookup_path(cfs, name, 1, base_name_out, parent_out);
}

int cbfs_create_file(fs_t* fs, const char* path,
                     cbfs_read_t read_cb, void* arg, kmode_t mode) {
  cbfs_t* cfs = fs_to_cbfs(fs);

  char name_start[VFS_MAX_FILENAME_LENGTH];
  cbfs_inode_t* parent = 0x0;
  int result = create_path(cfs, path, name_start, &parent);
  if (result) return result;
  if (!name_start[0]) return -EEXIST;  // root

  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* oldinode = 0x0;
  if (lookup_by_name(cfs, parent, name_start, &generated_inode, &oldinode) == 0)
    return -EEXIST;
  if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

  const int inode_num = alloc_inode_num(cfs);
  if (inode_num < 0) return inode_num;

  cbfs_inode_t* inode = create_inode(cfs, inode_num);
  inode->type = VNODE_REGULAR;
  inode->read_cb = read_cb;
  inode->arg = arg;
  inode->mode = mode;
  inode->uid = proc_current()->euid;
  inode->gid = proc_current()->egid;
  add_inode_to_vnode_table(cfs, inode);

  cbfs_entry_t* entry = create_entry(inode->num, name_start, NULL);
  insert_entry(parent, entry);

  return 0;
}

int cbfs_create_directory(fs_t* fs, const char* path,
                          cbfs_getdents_t getdents_cb, void* arg,
                          kmode_t mode) {
  cbfs_t* cfs = fs_to_cbfs(fs);

  char name_start[VFS_MAX_FILENAME_LENGTH];
  cbfs_inode_t* parent = 0x0;
  int result = create_path(cfs, path, name_start, &parent);
  if (result) return result;
  if (!name_start[0]) return -EEXIST;  // root

  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* oldinode = 0x0;
  if (lookup_by_name(cfs, parent, name_start, &generated_inode, &oldinode) == 0)
    return -EEXIST;
  if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

  const int inode_num = alloc_inode_num(cfs);
  if (inode_num < 0) return inode_num;

  cbfs_inode_t* inode = create_inode(cfs, inode_num);
  inode->type = VNODE_DIRECTORY;
  inode->getdents_cb = getdents_cb;
  inode->arg = arg;
  inode->mode = mode;
  inode->uid = proc_current()->euid;
  inode->gid = proc_current()->egid;
  add_inode_to_vnode_table(cfs, inode);

  create_directory_entries(parent->num, inode);

  cbfs_entry_t* entry = create_entry(inode->num, name_start, NULL);
  insert_entry(parent, entry);

  return 0;
}

int cbfs_create_symlink(fs_t* fs, const char* path, cbfs_readlink_t readlink_cb,
                        void* arg) {
  cbfs_t* cfs = fs_to_cbfs(fs);

  char name_start[VFS_MAX_FILENAME_LENGTH];
  cbfs_inode_t* parent = 0x0;
  int result = create_path(cfs, path, name_start, &parent);
  if (result) return result;
  if (!name_start[0]) return -EEXIST;  // root

  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* oldinode = 0x0;
  if (lookup_by_name(cfs, parent, name_start, &generated_inode, &oldinode) == 0)
    return -EEXIST;
  if (parent->type != VNODE_DIRECTORY) return -ENOTDIR;

  const int inode_num = alloc_inode_num(cfs);
  if (inode_num < 0) return inode_num;

  cbfs_inode_t* inode = create_inode(cfs, inode_num);
  inode->type = VNODE_SYMLINK;
  inode->readlink_cb = readlink_cb;
  inode->arg = arg;
  inode->mode = VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO;
  inode->uid = proc_current()->euid;
  inode->gid = proc_current()->egid;
  add_inode_to_vnode_table(cfs, inode);

  cbfs_entry_t* entry = create_entry(inode->num, name_start, NULL);
  insert_entry(parent, entry);

  return 0;
}

int cbfs_directory_set_getdents(fs_t* fs, const char* path,
                                cbfs_getdents_t getdents_cb, void* arg) {
  cbfs_t* cfs = fs_to_cbfs(fs);

  char name_start[VFS_MAX_FILENAME_LENGTH];
  cbfs_inode_t* parent = 0x0;
  int result = lookup_path(cfs, path, 0, name_start, &parent);
  if (result) return result;

  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  if (name_start[0]) {
    result = lookup_by_name(cfs, parent, name_start, &generated_inode, &inode);
    if (result) return result;
    KASSERT(parent->type == VNODE_DIRECTORY);
    if (inode->type != VNODE_DIRECTORY) return -ENOTDIR;
  } else {
    inode = parent;
  }

  inode->getdents_cb = getdents_cb;
  inode->arg = arg;

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
  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &generated_inode, &inode);
  if (result) return result;

  vnode->type = inode->type;
  vnode->uid = inode->uid;
  vnode->gid = inode->gid;
  vnode->mode = inode->mode;
  kstrcpy(vnode->fstype, vnode->fs->fstype);
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

  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &generated_inode, &inode);
  if (result) return result;

  inode->uid = vnode->uid;
  inode->gid = vnode->gid;
  inode->mode = vnode->mode;

  return 0;
}

static int cbfs_lookup(vnode_t* parent, const char* name) {
  cbfs_t* cfs = fs_to_cbfs(parent->fs);

  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* parent_inode = 0x0;
  int result = get_inode(cfs, parent->num, &generated_inode, &parent_inode);
  if (result) {
    klogfm(KL_VFS, WARNING,
           "cbfs: unable to get parent inode in cbfs_lookup(): %d\n", result);
    return result;
  }

  cbfs_inode_t generated_inode2 = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  result = lookup_by_name(cfs, parent_inode, name, &generated_inode2, &inode);
  if (result)
    return result;
  else
    return inode->num;
}

static int cbfs_mknod(vnode_t* parent, const char* name,
                        vnode_type_t type, apos_dev_t dev) {
  return -EACCES;
}

static int cbfs_mkdir(vnode_t* parent, const char* name) {
  return -EACCES;
}

static int cbfs_rmdir(vnode_t* parent, const char* name, const vnode_t* child) {
  return -EACCES;
}

static int cbfs_read(vnode_t* vnode, int offset, void* buf, int bufsize) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &generated_inode, &inode);
  if (result) return result;
  if (inode->type == VNODE_DIRECTORY) return -EISDIR;

  return inode->read_cb(vnode->fs, inode->arg, inode->num, offset, buf,
                        bufsize);
}

static int cbfs_write(vnode_t* vnode, int offset, const void* buf,
                        int bufsize) {
  return -EACCES;
}

static int cbfs_link(vnode_t* parent, vnode_t* vnode, const char* name) {
  return -EACCES;
}

static int cbfs_unlink(vnode_t* parent, const char* name, const vnode_t* child) {
  return -EACCES;
}

// Traverse the given list of cbfs_entry_ts and create dirent_ts from them.
// Skips the first entries_to_skip entries in the list.  Returns the *total*
// number of bytes written (including the incoming bytes_to_write), or an error,
// and increments entries_seen_out by the number of *entries* written or
// skipped.  The offset is used to calculate the offset for the generated
// dirent_ts, so it must be the absolute offset from the start of the directory.
static int getdents_from_list(const list_t* list, const int entries_to_skip,
                              const int offset, void* const outbuf,
                              const int outbufsize, int bytes_written,
                              int* const entries_seen_out) {
  list_link_t* n = list->head;
  int idx = 0;
  while (n && idx < entries_to_skip) {
    n = n->next;
    idx++;
    (*entries_seen_out)++;
  }

  if (!n) return bytes_written;

  while (1) {
    if (!n) break;
    cbfs_entry_t* entry = container_of(n, cbfs_entry_t, link);

    const int dirent_len = align_up(
        sizeof(kdirent_t) + kstrlen(entry->name) + 1, alignof(kdirent_t));
    if (bytes_written + dirent_len > outbufsize) break;

    kdirent_t* d = (kdirent_t*)(((const char*)outbuf) + bytes_written);
    d->d_ino = entry->num;
    d->d_offset = offset + idx + 1;
    d->d_reclen = dirent_len;
    kstrcpy(d->d_name, entry->name);

    bytes_written += dirent_len;
    n = n->next;
    idx++;
    (*entries_seen_out)++;
  }
  return bytes_written;
}

static int cbfs_getdents(vnode_t* vnode, const int offset, void* outbuf,
                         int outbufsize) {
  KASSERT(vnode->type == VNODE_DIRECTORY);
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &generated_inode, &inode);
  if (result) return result;

  int bytes_written = 0;
  int entries_seen = 0;
  result = getdents_from_list(&inode->entries,
                              offset,  // Skip |offset| entries
                              0,       // Don't double-count the offset.
                              outbuf, outbufsize, bytes_written, &entries_seen);
  if (result < 0) return result;
  bytes_written = result;

  if (inode->getdents_cb) {
    list_t list = LIST_INIT;
    const int kCbfsEntryBufSize = 1000;
    char cbfs_entry_buf[kCbfsEntryBufSize];
    const int num_dynamic_to_skip = max(0, offset - entries_seen);
    result = inode->getdents_cb(vnode->fs, inode->num, inode->arg,
                                num_dynamic_to_skip, &list, cbfs_entry_buf,
                                kCbfsEntryBufSize);
    if (result < 0) return result;
    entries_seen += num_dynamic_to_skip;

    result =
        getdents_from_list(&list,
                           0,  // Don't skip entries (getdents_cb already did)
                           entries_seen,  // ...but set the offset correctly.
                           outbuf, outbufsize, bytes_written, &entries_seen);
    if (result < 0) return result;
    bytes_written = result;
  }

  return bytes_written;
}

static int cbfs_stat(vnode_t* vnode, apos_stat_t* stat_out) {
  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &generated_inode, &inode);
  if (result) return result;

  switch (inode->type) {
    case VNODE_REGULAR: inode->mode = VFS_S_IFREG; break;
    case VNODE_DIRECTORY: inode->mode = VFS_S_IFDIR; break;
    case VNODE_SYMLINK: inode->mode = VFS_S_IFLNK; break;
    default: die("invalid vnode filetype in cbfs");
  }
  stat_out->st_mode |= inode->mode;
  stat_out->st_nlink = (inode->type == VNODE_DIRECTORY) ? 2 : 1;
  stat_out->st_rdev = kmakedev(0, 0);
  stat_out->st_size = 2 * sizeof(kdirent_t) + 5;
  stat_out->st_blksize = 512;
  stat_out->st_blocks = 1;
  return 0;
}

static int cbfs_symlink(vnode_t* parent, const char* name, const char* path) {
  return -EACCES;
}

static int cbfs_readlink(vnode_t* vnode, char* buf, int bufsize) {
  KASSERT(vnode->type == VNODE_SYMLINK);

  cbfs_t* cfs = fs_to_cbfs(vnode->fs);
  cbfs_inode_t generated_inode = INIT_INODE;
  cbfs_inode_t* inode = 0x0;
  int result = get_inode(cfs, vnode->num, &generated_inode, &inode);
  if (result) return result;

  KASSERT(inode->type == VNODE_SYMLINK);
  return inode->readlink_cb(vnode->fs, inode->arg, inode->num, buf, bufsize);
}

static int cbfs_truncate(vnode_t* node, koff_t length) {
  return -EACCES;
}

static int cbfs_read_page(vnode_t* vnode, int page_offset, void* buf) {
  int result = cbfs_read(vnode, page_offset * PAGE_SIZE, buf, PAGE_SIZE);
  return (result < 0) ? result : 0;
}

static int cbfs_write_page(vnode_t* vnode, int page_offset, const void* buf) {
  return -ENOTSUP;
}
