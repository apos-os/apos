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

#ifndef APOO_COMMON_REFCOUNT_H
#define APOO_COMMON_REFCOUNT_H

#include "common/attributes.h"
#include "proc/spinlock.h"

// Simple interrupt-safe atomic refcount.
// TODO(aoates): replace with a native atomic.
typedef struct {
  int ref;
  kspinlock_intsafe_t spin;
} refcount_t;

#define REFCOUNT_INIT ((refcount_t){1, KSPINLOCK_NORMAL_INIT_STATIC})

// Increment the refcount.
void refcount_inc(refcount_t* ref);

// Decrement the refcount and return its new value.  If returns zero, the caller
// held the last refcount and can safely clean up the object.
int refcount_dec(refcount_t* ref);

#endif
