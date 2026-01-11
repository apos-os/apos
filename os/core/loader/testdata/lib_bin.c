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

void _start(void) {
  testlib_calls_t c = {};
  funcA(&c);
  // TODO(aoates): when relocations are implemented, verify the outcome of the
  // dynamic execution is correct.
  // TODO(aoates): test global data relocations in addition to function calls.
  // TODO(aoates): test SONAME overrides with this.
}
