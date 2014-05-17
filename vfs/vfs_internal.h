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

// Internal definitions and utilies to be used within the VFS module.
#ifndef APOO_VFS_VFS_INTERNAL_H
#define APOO_VFS_VFS_INTERNAL_H

#include "common/hashtable.h"
#include "vfs/file.h"
#include "vfs/fs.h"

// How many files can be open, globally, at once.
#define VFS_MAX_FILES 128

extern fs_t* g_root_fs;
extern htbl_t g_vnode_cache;
extern file_t* g_file_table[VFS_MAX_FILES];

#endif
