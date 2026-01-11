// Copyright 2026 Andrew Oates.  All Rights Reserved.
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
#include "os/core/loader/testdata/libs_header.h"
IMPL_FUNC(lib4_, funcE, {})  // Leaf function

// These are the same as funcA() and funcB() in lib1 and lib2, but shouldn't be
// called due to library load ordering.
IMPL_FUNC(lib4_, funcA, {})
IMPL_FUNC(lib4_, funcB, {})
