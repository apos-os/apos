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

// Helper for initializing components easily.
#ifndef APOO_COMMON_INITER_H
#define APOO_COMMON_INITER_H

#include "proc/spinlock.h"

// Initer data.  Each initer_t is initialized exactly once, atomically.
typedef struct {
  kspinlock_t mu;
  bool initialized;
} initer_t;

#define INITER {KSPINLOCK_NORMAL_INIT_STATIC, false}

// Initialize the initer, if it hasn't already.  The initialization function is
// guaranteed to be called exactly once.  When this returns, it will have
// finished.
void initer(initer_t* init, void (*fn)(initer_t*));

#endif
