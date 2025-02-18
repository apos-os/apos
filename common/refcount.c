// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "common/refcount.h"

#include "common/kassert.h"
#include "proc/spinlock.h"

void refcount_inc(refcount_t* ref) {
  atomic_add_relaxed(&ref->ref, 1);
}

int refcount_dec(refcount_t* ref) {
  int result = (int)atomic_sub_acq_rel(&ref->ref, 1);
  KASSERT_DBG(result >= 0);
  return result;
}

int refcount_get(const refcount_t* ref) {
  return (int)atomic_load_relaxed(&ref->ref);
}
