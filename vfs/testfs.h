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

// A simple test filesystem that has a single read-only root directory.
#ifndef APOO_VFS_TESTFS_H
#define APOO_VFS_TESTFS_H

#include "vfs/fs.h"

fs_t* testfs_create(void);
void testfs_free(fs_t* fs);

int testfs_create_path(const char* source, unsigned long flags,
                       const void* data, size_t data_len, fs_t** fs_out);

#endif
