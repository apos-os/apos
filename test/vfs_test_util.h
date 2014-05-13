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

#ifndef APOO_TEST_VFS_TEST_UTIL_H
#define APOO_TEST_VFS_TEST_UTIL_H

#include "vfs/stat.h"

// Convert a "rwxr-xrw-"-style string into a mode_t.
mode_t str_to_mode(const char* mode_str);

// Create the given file with the given mode.
void create_file(const char* path, const char* mode);

#endif
