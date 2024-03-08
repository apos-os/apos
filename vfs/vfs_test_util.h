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

// Utilities for use in tests and debugging.
#ifndef APOO_VFS_VFS_TEST_UTIL_H
#define APOO_VFS_VFS_TEST_UTIL_H

#include <stdbool.h>

// Log the current vnode cache.
void vfs_log_cache(void);

// Return how many vnodes are currently in the cache.
int vfs_cache_size(void);

// Looks up the given path and returns the refcount of the corresponding vnode,
// 0 if there is no matching vnode in the cache, or -errno if the path can't be
// found.
//
// Should only be used in tests.
int vfs_get_vnode_refcount_for_path(const char* path);

// Returns the vnode number at the given path, or -errno if the path can't be
// found.
//
// Should only be used in tests.
int vfs_get_vnode_for_path(const char* path);

// Force an out-of-files or out-of-fds condition for tests.
void vfs_set_force_no_files(bool f);
bool vfs_get_force_no_files(void);

// Make the given file descriptor non-blocking.
// TODO(aoates): ditch this when fcntl() is implemented.
void vfs_make_nonblock(int fd);
void vfs_make_blocking(int fd);

#endif
