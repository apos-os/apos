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

// Wrappers around core spinlock functions that only instrument with TSAN when
// TSAN_CORE mode is enabled.
//
// Core in core thread modules should use the tsc_foo() versions of functions.
// These will normally resolve to non-TSAN versions of the functions, unless
// TSAN_CORE is enabled.
//
// Those functions should almost certainly also use the TSAN_CORE_FN attribute,
// which will disable TSAN unless TSAN_CORE is enabled.  Otherwise, due to the
// lack of TSAN instrumentation on the locking, TSAN will find false positives.
#ifndef APOO_SANITIZERS_TSAN_SPINLOCK_CORE_H
#define APOO_SANITIZERS_TSAN_SPINLOCK_CORE_H

#include "common/attributes.h"
#include "common/config.h"

// Helpers for declarations below.
#if ENABLE_TSAN_CORE
# define TSAN_CORE_FN
# define _TSAN_CORE_SUFFIX
#else
# define TSAN_CORE_FN NO_TSAN
# define _TSAN_CORE_SUFFIX _no_tsan
#endif

#define _TSAN_CORE_CONCAT2(a, b) a##b
#define _TSAN_CORE_CONCAT(a, b) _TSAN_CORE_CONCAT2(a, b)
#define _TSAN_CORE_NAME(func) _TSAN_CORE_CONCAT(func, _TSAN_CORE_SUFFIX)

// Declarations for all tsc_* functions.
// TODO(tsan): write tsan tests for each of these that verify that they don't
// synchronize.  Also, ideally, write some tsan tests that fail if these aren't
// used correctly in the scheduler code.
#define tsc_kspin_lock_int _TSAN_CORE_NAME(kspin_lock_int)
#define tsc_kspin_unlock_int _TSAN_CORE_NAME(kspin_unlock_int)
#define tsc_kspin_unlock_int2 _TSAN_CORE_NAME(kspin_unlock_int2)
#define tsc_kspin_lock_early _TSAN_CORE_NAME(kspin_lock_early)
#define tsc_kspin_unlock_early _TSAN_CORE_NAME(kspin_unlock_early)
#define tsc_kspin_unlock_early2 _TSAN_CORE_NAME(kspin_unlock_early2)

#endif
