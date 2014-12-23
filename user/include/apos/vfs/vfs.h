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

// Filesystem constants.
#ifndef APOO_USER_VFS_VFS_H
#define APOO_USER_VFS_VFS_H

// Syscall flags.
#define VFS_MODE_MASK  0x03  // TODO(aoates): replace with VFS_O_ACCMODE
#define VFS_O_RDONLY   0x00
#define VFS_O_WRONLY   0x01
#define VFS_O_RDWR     0x02
#define VFS_O_ACCMODE  VFS_MODE_MASK

#define VFS_O_APPEND   0x04
#define VFS_O_CREAT    0x08
#define VFS_O_TRUNC    0x10  // TODO(aoates)
#define VFS_O_EXCL     0x20  // TODO(aoates)
#define VFS_O_NONBLOCK 0x40  // TODO(aoates)
#define VFS_O_NOCTTY   0x80

// Used internally (i.e. not exposed to userspace) to indicate a file that will
// be executed.  If set, vfs_open will check that the file is executable.
#define VFS_O_INTERNAL_EXEC 0x20

#define VFS_SEEK_SET 1
#define VFS_SEEK_CUR 2
#define VFS_SEEK_END 3

#define F_OK 0x1
#define R_OK 0x2
#define W_OK 0x4
#define X_OK 0x8

#endif
