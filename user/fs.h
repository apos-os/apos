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

// Filesystem syscalls.
#ifndef APOO_USER_FS_H
#define APOO_USER_FS_H

#include <stdint.h>

#include "vfs/vfs.h"

#define O_RDONLY VFS_O_RDONLY
#define O_WRONLY VFS_O_WRONLY
#define O_RDWR VFS_O_RDWR

#define O_APPEND VFS_O_APPEND
#define O_CREAT VFS_O_CREAT
#define O_TRUNC VFS_O_TRUNC

// File types.
#define S_IFREG VFS_S_IFREG
#define S_IFCHR VFS_S_IFCHR
#define S_IFBLK VFS_S_IFBLK

#define SEEK_SET VFS_SEEK_SET
#define SEEK_CUR VFS_SEEK_CUR
#define SEEK_END VFS_SEEK_END

int open(const char* path, uint32_t flags);
int close(int fd);
int mkdir(const char* path);
int mknod(const char* path, uint32_t mode, apos_dev_t dev);
int rmdir(const char* path);
int unlink(const char* path);
int read(int fd, void* buf, int count);
int write(int fd, const void* buf, int count);
int seek(int fd, int offset, int whence);
int getdents(int fd, dirent_t* buf, int count);
int getcwd(char* path_out, int size);
int chdir(const char* path);

#endif
