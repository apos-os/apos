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

#include <sys/types.h>

// Manual wrappers around the syscalls used by the loader code, since it doesn't
// link against newlib/libc.  Unlike the stdlib variants, these return -error
// rather than setting errno.
// TODO(aoates): replace this (and syscalls.c) with auto-generated stubs.
int ld_close(int fd);
int ld_open(const char* path, int flags, apos_mode_t mode);
ssize_t ld_write(int fd, const void* buf, size_t count);
ssize_t ld_read(int fd, void* buf, size_t count);
int ld_exit(int status);

#endif
