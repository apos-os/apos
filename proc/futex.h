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
#ifndef APOO_PROC_FUTEX_H
#define APOO_PROC_FUTEX_H

#include <stdint.h>

#include "user/include/apos/futex.h"
#include "user/include/apos/time_types.h"

// Atomically compare-and-block.  If *uaddr == val, blocks on the futex
// associated with uaddr.
int futex_wait(uint32_t* uaddr, uint32_t val,
               const struct apos_timespec* timeout_relative);

// Wake up to val waiters queued on the futex associated with uaddr.
int futex_wake(uint32_t* uaddr, uint32_t val);

// Execute a futex operation (per Linux's futex syscall).
int futex_op(uint32_t* uaddr, int futex_op, uint32_t val,
             const struct apos_timespec* timeout, uint32_t* uaddr2,
             uint32_t val3);

#endif
