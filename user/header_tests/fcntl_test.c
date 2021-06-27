// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#include <fcntl.h>

#include "user/include/apos/vfs/vfs.h"

_Static_assert(O_RDONLY == VFS_O_RDONLY, "Mismatched header definitions (O_RDONLY vs VFS_O_RDONLY)");
_Static_assert(O_WRONLY == VFS_O_WRONLY, "Mismatched header definitions (O_WRONLY vs VFS_O_WRONLY)");
_Static_assert(O_RDWR == VFS_O_RDWR, "Mismatched header definitions (O_RDWR vs VFS_O_RDWR)");
_Static_assert(O_ACCMODE == VFS_O_ACCMODE, "Mismatched header definitions (O_ACCMODE vs VFS_O_ACCMODE)");

_Static_assert(O_APPEND == VFS_O_APPEND, "Mismatched header definitions (O_APPEND vs VFS_O_APPEND)");
_Static_assert(O_CREAT == VFS_O_CREAT, "Mismatched header definitions (O_CREAT vs VFS_O_CREAT)");
_Static_assert(O_TRUNC == VFS_O_TRUNC, "Mismatched header definitions (O_TRUNC vs VFS_O_TRUNC)");
_Static_assert(O_EXCL == VFS_O_EXCL, "Mismatched header definitions (O_EXCL vs VFS_O_EXCL)");
_Static_assert(O_NONBLOCK == VFS_O_NONBLOCK, "Mismatched header definitions (O_NONBLOCK vs VFS_O_NONBLOCK)");
_Static_assert(O_NOCTTY == VFS_O_NOCTTY, "Mismatched header definitions (O_NOCTTY vs VFS_O_NOCTTY)");
_Static_assert(O_DIRECTORY == VFS_O_DIRECTORY, "Mismatched header definitions (O_DIRECTORY vs VFS_O_DIRECTORY)");
_Static_assert(O_NOFOLLOW == VFS_O_NOFOLLOW, "Mismatched header definitions (O_NOFOLLOW vs VFS_O_NOFOLLOW)");

_Static_assert(SEEK_SET == VFS_SEEK_SET, "Mismatched header definitions (SEEK_SET vs VFS_SEEK_SET)");
_Static_assert(SEEK_CUR == VFS_SEEK_CUR, "Mismatched header definitions (SEEK_CUR vs VFS_SEEK_CUR)");
_Static_assert(SEEK_END == VFS_SEEK_END, "Mismatched header definitions (SEEK_END vs VFS_SEEK_END)");
