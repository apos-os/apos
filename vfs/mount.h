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

#ifndef APOO_VFS_MOUNT_H
#define APOO_VFS_MOUNT_H

#include "vfs/fs.h"

// Mount the given filesystem at the given path, setting its fsid as needed.
// Returns 0 if the mount succeeds, or -error if it fails.
int vfs_mount_fs(const char* path, fs_t* fs);

// Unmount the filesystem mounted at the given path.  If successful, returns 0
// and sets |fs_out| to the fs_t that was previously mounted at that point (and
// which has now been removed from the filesystem table).
int vfs_unmount_fs(const char* path, fs_t** fs_out);

// Return the number of currently-mounted filesystems, including the root
// filesystem.
int vfs_mounted_fs_count(void);

#endif
