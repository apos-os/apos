// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_CORE_LOADER_SYSCALLS_H
#define APOO_OS_CORE_LOADER_SYSCALLS_H

#include <apos/vfs/stat.h>
#include <sys/types.h>

// Manual wrappers around the syscalls used by the loader code, since it doesn't
// link against newlib/libc.  Unlike the stdlib variants, these return -error
// rather than setting errno.
int ld_open(const char* path, int flags, apos_mode_t mode);
int ld_close(int fd);
ssize_t ld_read(int fd, void* buf, size_t count);
ssize_t ld_write(int fd, const void* buf, size_t count);
int ld_fstat(int fd, apos_stat_t* stat);
apos_off_t ld_lseek(int fd, apos_off_t offset, int whence);
int ld_exit(int status);
int ld_mmap(void* addr_inout, size_t length, int prot, int flags, int fd,
            apos_off_t offset);
int ld_munmap(void* addr, size_t length);

#endif
