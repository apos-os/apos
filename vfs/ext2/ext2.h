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

#ifndef APOO_VFS_EXT2_EXT2_H
#define APOO_VFS_EXT2_EXT2_H

#include <stdint.h>

#include "user/dev.h"
#include "vfs/fs.h"

// Initialize a new ext2fs and return it.  The ext2fs is NOT mounted.
fs_t* ext2_create_fs(void);

// Destroy an ext2fs.  The ext2fs must NOT be mounted.
void ext2_destroy_fs(fs_t* fs);

// Mount an ext2fs created with ext2_create_fs() on the given device.  Returns 0
// on success.
int ext2_mount(fs_t* fs, apos_dev_t dev);

#endif
