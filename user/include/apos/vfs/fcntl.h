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

#ifndef APOO_USER_INCLUDE_APOS_VFS_FCNTL_H
#define APOO_USER_INCLUDE_APOS_VFS_FCNTL_H

// Supported commands for fcntl().
#define VFS_F_DUPFD         1
#define VFS_F_DUPFD_CLOEXEC 2
#define VFS_F_GETFD         3
#define VFS_F_SETFD         4

#if !__APOS_BUILDING_KERNEL__
#define F_DUPFD VFS_F_DUPFD
#define F_DUPFD_CLOEXEC VFS_F_DUPFD_CLOEXEC
#define F_GETFD VFS_F_GETFD
#define F_SETFD VFS_F_SETFD
#endif

#endif
