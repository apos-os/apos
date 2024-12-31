// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "sanitizers/tsan/vector_clock.h"

#include "common/math.h"
#include "sanitizers/tsan/tsan_params.h"

void tsan_vc_init(tsan_vc_t* vc) {
  for (int i = 0; i < TSAN_THREAD_SLOTS; ++i) {
    vc->ts[i] = 0;
  }
}

void tsan_vc_acquire(tsan_vc_t* dst, const tsan_vc_t* src) {
  for (int i = 0; i < TSAN_THREAD_SLOTS; ++i) {
    dst->ts[i] = max(dst->ts[i], src->ts[i]);
  }
}
