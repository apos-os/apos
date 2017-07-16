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

#ifndef APOO_VFS_FSID_H
#define APOO_VFS_FSID_H

// A unique ID assigned to each mounted filesystem.  Corresponds to the
// filesystem's index in the filesystem table.
typedef int fsid_t;

// fsid_t corresponding to no mounted filesystem.
#define VFS_FSID_NONE -1

// The root fsid.
#define VFS_ROOT_FS 0

// The FIFO anonymous fsid.
#define VFS_FIFO_FS 1

// The socket anonymous fsid.
#define VFS_SOCKET_FS 2

#endif
