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

#ifndef APOO_COMMON_ATTRIBUTES_H
#define APOO_COMMON_ATTRIBUTES_H

#define ALWAYS_INLINE __attribute__((always_inline))

// Use NO_TSAN for functions whose accesses should not be annotated/intercepted.
// The functions themselves will still be instrumented (function entry/exit).
#define NO_TSAN __attribute__((no_sanitize("thread")))

// Use NO_SANITIZER to prevent _all_ instrumentation by sanitizers, including
// annotating function entry/exit.  Use this sparingly, only needed for
// functions that are used by the sanitizers themselves to determine running
// state.
#if defined(__clang__) && defined(__has_feature) && __has_feature(thread_sanitizer)
#define NO_SANITIZER __attribute__((disable_sanitizer_instrumentation))
#else
#define NO_SANITIZER
#endif

#endif
