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

#ifndef APOO_VFS_SPECIAL_H
#define APOO_VFS_SPECIAL_H

#include "user/include/apos/dev.h"
#include "vfs/vnode.h"

// Read and write to/from a device special file.  Used internally by the VFS.
int special_device_read(vnode_type_t type, apos_dev_t dev, int offset,
                        void* buf, int len, int flags);
int special_device_write(vnode_type_t type, apos_dev_t dev, int offset,
                         const void* buf, int len, int flags);

#endif
