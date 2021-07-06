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

#include <unistd.h>

#include "user/include/apos/vfs/vfs.h"

_Static_assert(F_OK == VFS_F_OK, "Mismatched header definitions (F_OK vs VFS_F_OK)");
_Static_assert(R_OK == VFS_R_OK, "Mismatched header definitions (R_OK vs VFS_R_OK)");
_Static_assert(W_OK == VFS_W_OK, "Mismatched header definitions (W_OK vs VFS_W_OK)");
_Static_assert(X_OK == VFS_X_OK, "Mismatched header definitions (X_OK vs VFS_X_OK)");
