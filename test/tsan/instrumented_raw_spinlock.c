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
#include <stdint.h>

#if !__has_feature(thread_sanitizer)
#error TSAN must be enabled in this module
#endif

// Must be first!
#define RAWSP_DISABLE_TSAN 0
#include "proc/raw_spinlock.h"

#include "test/tsan/instrumented.h"

void tsan_raw_lock_with_tsan(raw_spinlock_t* rsp) {
  raw_spin_lock(rsp);
}

void tsan_raw_unlock_with_tsan(raw_spinlock_t* rsp) {
  raw_spin_unlock(rsp);
}
